/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor.h"

#include "gumcodesegment.h"
#include "guminterceptor-priv.h"
#include "gumlibc.h"
#include "gummemory.h"
#include "gumprocess.h"
#include "gumtls.h"

#include <string.h>

#ifdef HAVE_MIPS
# define GUM_INTERCEPTOR_CODE_SLICE_SIZE 1024
#else
# define GUM_INTERCEPTOR_CODE_SLICE_SIZE 256
#endif

#define GUM_INTERCEPTOR_LOCK(o) g_rec_mutex_lock (&(o)->mutex)
#define GUM_INTERCEPTOR_UNLOCK(o) g_rec_mutex_unlock (&(o)->mutex)

typedef struct _GumInterceptorTransaction GumInterceptorTransaction;
typedef guint GumInstrumentationError;
typedef struct _GumDestroyTask GumDestroyTask;
typedef struct _GumUpdateTask GumUpdateTask;
typedef struct _GumSuspendOperation GumSuspendOperation;
typedef struct _ListenerEntry ListenerEntry;
typedef struct _InterceptorThreadContext InterceptorThreadContext;
typedef struct _GumInvocationStackEntry GumInvocationStackEntry;
typedef struct _ListenerDataSlot ListenerDataSlot;
typedef struct _ListenerInvocationState ListenerInvocationState;

typedef void (* GumUpdateTaskFunc) (GumInterceptor * self,
    GumFunctionContext * ctx, gpointer prologue);

struct _GumInterceptorTransaction
{
  gboolean is_dirty;
  gint level;
  GQueue * pending_destroy_tasks;
  GHashTable * pending_update_tasks;

  GumInterceptor * interceptor;
};

struct _GumInterceptor
{
#ifndef GUM_DIET
  GObject parent;
#else
  GumObject parent;
#endif

  GRecMutex mutex;

  GHashTable * function_by_address;

  GumInterceptorBackend * backend;
  GumCodeAllocator allocator;

  volatile guint selected_thread_id;

  GumInterceptorTransaction current_transaction;
};

enum _GumInstrumentationError
{
  GUM_INSTRUMENTATION_ERROR_NONE,
  GUM_INSTRUMENTATION_ERROR_WRONG_SIGNATURE,
  GUM_INSTRUMENTATION_ERROR_POLICY_VIOLATION,
  GUM_INSTRUMENTATION_ERROR_WRONG_TYPE,
};

struct _GumDestroyTask
{
  GumFunctionContext * ctx;
  GDestroyNotify notify;
  gpointer data;
};

struct _GumUpdateTask
{
  GumFunctionContext * ctx;
  GumUpdateTaskFunc func;
};

struct _GumSuspendOperation
{
  GumThreadId current_thread_id;
  GQueue suspended_threads;
};

struct _ListenerEntry
{
#ifndef GUM_DIET
  GumInvocationListenerInterface * listener_interface;
  GumInvocationListener * listener_instance;
#else
  union
  {
    GumInvocationListener * listener_interface;
    GumInvocationListener * listener_instance;
  };
#endif
  gpointer function_data;
};

struct _InterceptorThreadContext
{
  GumInvocationBackend listener_backend;
  GumInvocationBackend replacement_backend;

  gint ignore_level;

  GumInvocationStack * stack;

  GArray * listener_data_slots;
};

struct _GumInvocationStackEntry
{
  GumFunctionContext * function_ctx;
  gpointer caller_ret_addr;
  GumInvocationContext invocation_context;
  GumCpuContext cpu_context;
  guint8 listener_invocation_data[GUM_MAX_LISTENERS_PER_FUNCTION]
      [GUM_MAX_LISTENER_DATA];
  gboolean calling_replacement;
  gint original_system_error;
};

struct _ListenerDataSlot
{
  GumInvocationListener * owner;
  guint8 data[GUM_MAX_LISTENER_DATA];
};

struct _ListenerInvocationState
{
  GumPointCut point_cut;
  ListenerEntry * entry;
  InterceptorThreadContext * interceptor_ctx;
  guint8 * invocation_data;
};

#ifndef GUM_DIET
static void gum_interceptor_dispose (GObject * object);
static void gum_interceptor_finalize (GObject * object);

static void the_interceptor_weak_notify (gpointer data,
    GObject * where_the_object_was);
#endif
static GumReplaceReturn gum_interceptor_replace_with_type (
    GumInterceptor * self, GumInterceptorType type, gpointer function_address,
    gpointer replacement_function, gpointer replacement_data,
    gpointer * original_function);
static GumFunctionContext * gum_interceptor_instrument (GumInterceptor * self,
    GumInterceptorType type, gpointer function_address,
    GumInstrumentationError * error);
static void gum_interceptor_activate (GumInterceptor * self,
    GumFunctionContext * ctx, gpointer prologue);
static void gum_interceptor_deactivate (GumInterceptor * self,
    GumFunctionContext * ctx, gpointer prologue);

static void gum_interceptor_transaction_init (
    GumInterceptorTransaction * transaction, GumInterceptor * interceptor);
static void gum_interceptor_transaction_destroy (
    GumInterceptorTransaction * transaction);
static void gum_interceptor_transaction_begin (
    GumInterceptorTransaction * self);
static void gum_interceptor_transaction_end (GumInterceptorTransaction * self);
static gboolean gum_maybe_suspend_thread (const GumThreadDetails * details,
    gpointer user_data);
static void gum_interceptor_transaction_schedule_destroy (
    GumInterceptorTransaction * self, GumFunctionContext * ctx,
    GDestroyNotify notify, gpointer data);
static void gum_interceptor_transaction_schedule_update (
    GumInterceptorTransaction * self, GumFunctionContext * ctx,
    GumUpdateTaskFunc func);

static GumFunctionContext * gum_function_context_new (
    GumInterceptor * interceptor, gpointer function_address,
    GumInterceptorType type);
static void gum_function_context_finalize (GumFunctionContext * function_ctx);
static void gum_function_context_destroy (GumFunctionContext * function_ctx);
static void gum_function_context_perform_destroy (
    GumFunctionContext * function_ctx);
static gboolean gum_function_context_is_empty (
    GumFunctionContext * function_ctx);
static void gum_function_context_add_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener,
    gpointer function_data);
static void gum_function_context_remove_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);
static void listener_entry_free (ListenerEntry * entry);
static gboolean gum_function_context_has_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);
static ListenerEntry ** gum_function_context_find_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);
static ListenerEntry ** gum_function_context_find_taken_listener_slot (
    GumFunctionContext * function_ctx);
static void gum_function_context_fixup_cpu_context (
    GumFunctionContext * function_ctx, GumCpuContext * cpu_context);

static InterceptorThreadContext * get_interceptor_thread_context (void);
static void release_interceptor_thread_context (
    InterceptorThreadContext * context);
static InterceptorThreadContext * interceptor_thread_context_new (void);
static void interceptor_thread_context_destroy (
    InterceptorThreadContext * context);
static gpointer interceptor_thread_context_get_listener_data (
    InterceptorThreadContext * self, GumInvocationListener * listener,
    gsize required_size);
static void interceptor_thread_context_forget_listener_data (
    InterceptorThreadContext * self, GumInvocationListener * listener);
static GumInvocationStackEntry * gum_invocation_stack_push (
    GumInvocationStack * stack, GumFunctionContext * function_ctx,
    gpointer caller_ret_addr);
static gpointer gum_invocation_stack_pop (GumInvocationStack * stack);
static GumInvocationStackEntry * gum_invocation_stack_peek_top (
    GumInvocationStack * stack);

static gpointer gum_interceptor_resolve (GumInterceptor * self,
    gpointer address);
static gboolean gum_interceptor_has (GumInterceptor * self,
    gpointer function_address);

static gpointer gum_page_address_from_pointer (gpointer ptr);
static gint gum_page_address_compare (gconstpointer a, gconstpointer b);

#ifndef GUM_DIET
G_DEFINE_TYPE (GumInterceptor, gum_interceptor, G_TYPE_OBJECT)
#endif

static GMutex _gum_interceptor_lock;
static GumInterceptor * _the_interceptor = NULL;

static GumSpinlock gum_interceptor_thread_context_lock = GUM_SPINLOCK_INIT;
static GHashTable * gum_interceptor_thread_contexts;
static GPrivate gum_interceptor_context_private =
    G_PRIVATE_INIT ((GDestroyNotify) release_interceptor_thread_context);
static GumTlsKey gum_interceptor_guard_key;

static GumInvocationStack _gum_interceptor_empty_stack = { NULL, 0 };

#ifndef GUM_DIET



// gum_interceptor_class_init() is a standard GObjectClass initialization
//function which sets up the class' dispose and finalize functions for proper
//memory management.
static void
gum_interceptor_class_init (GumInterceptorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_interceptor_dispose;
  object_class->finalize = gum_interceptor_finalize;
}

#endif



//This function initializes the GumInterceptor by creating a new hash table
//and allocating memory for a thread-specific key. This is necessary to enable
//interception of functions in different threads.
void
_gum_interceptor_init (void)
{
  gum_interceptor_thread_contexts = g_hash_table_new_full (NULL, NULL,
      (GDestroyNotify) interceptor_thread_context_destroy, NULL);

  gum_interceptor_guard_key = gum_tls_key_new ();
}



// This function serves to clean up after the gum_interceptor_init() function.
//It frees the memory allocated to the TLS key used for guarding against re-
//entrancy, and also frees any resources associated with thread contexts stored in
//a hash table.
void
_gum_interceptor_deinit (void)
{
  gum_tls_key_free (gum_interceptor_guard_key);

  g_hash_table_unref (gum_interceptor_thread_contexts);
  gum_interceptor_thread_contexts = NULL;
}



// This function initializes the GumInterceptor object by setting up a
//recursive mutex, creating a hash table to store address-function mappings, and
//initializing an allocator for code slices. It also sets up the current
//transaction of the interceptor.
static void
gum_interceptor_init (GumInterceptor * self)
{
  g_rec_mutex_init (&self->mutex);

  self->function_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_function_context_destroy);

  gum_code_allocator_init (&self->allocator, GUM_INTERCEPTOR_CODE_SLICE_SIZE);

  gum_interceptor_transaction_init (&self->current_transaction, self);
}



// This function is responsible for disposing the GumInterceptor instance. It
//begins a transaction, sets it to dirty and removes all functions from the
//address-function mapping table before committing the transaction.
static void
gum_interceptor_do_dispose (GumInterceptor * self)
{
  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  self->current_transaction.is_dirty = TRUE;

  g_hash_table_remove_all (self->function_by_address);

  gum_interceptor_transaction_end (&self->current_transaction);
  GUM_INTERCEPTOR_UNLOCK (self);
}



// gum_interceptor_do_finalize is a function responsible for cleaning up
//memory and resources used by GumInterceptor. It destroys the current
//transaction, destroys the backend, clears the mutex, unreferences the address-
//to-function hash table and frees up any allocated code via gum_code_allocator.
static void
gum_interceptor_do_finalize (GumInterceptor * self)
{
  gum_interceptor_transaction_destroy (&self->current_transaction);

  if (self->backend != NULL)
    _gum_interceptor_backend_destroy (self->backend);

  g_rec_mutex_clear (&self->mutex);

  g_hash_table_unref (self->function_by_address);

  gum_code_allocator_free (&self->allocator);
}

#ifndef GUM_DIET



// gum_interceptor_dispose is a function from the GObject class that handles
//disposing of an object. It calls the gum_interceptor_do_dispose method to
//perform any actions needed before calling the parent's dispose method.
static void
gum_interceptor_dispose (GObject * object)
{
  gum_interceptor_do_dispose (GUM_INTERCEPTOR (object));

  G_OBJECT_CLASS (gum_interceptor_parent_class)->dispose (object);
}



// gum_interceptor_finalize is a GObject finalization function that calls the
//gum_interceptor_do_finalize on the given GumInterceptor object, and then calls
//its parent class's finalization function. The goal of this function is to
//properly free resources associated with the GumInterceptor object when it goes
//out of scope.
static void
gum_interceptor_finalize (GObject * object)
{
  gum_interceptor_do_finalize (GUM_INTERCEPTOR (object));

  G_OBJECT_CLASS (gum_interceptor_parent_class)->finalize (object);
}

#else



// gum_interceptor_finalize() is a function used to clean up and free
//resources associated with the GumInterceptor object. It sets the global
//_the_interceptor variable to NULL and calls both gum_interceptor_do_dispose()
//and gum_interceptor_do_finalize(), which do additional cleaning of resources for
//this object before it's destroyed.
static void
gum_interceptor_finalize (GumObject * object)
{
  GumInterceptor * self = GUM_INTERCEPTOR (object);

  g_mutex_lock (&_gum_interceptor_lock);
  if (_the_interceptor == self)
    _the_interceptor = NULL;
  g_mutex_unlock (&_gum_interceptor_lock);

  gum_interceptor_do_dispose (self);
  gum_interceptor_do_finalize (self);
}

#endif



// This function obtains an instance of the GumInterceptor object and
//initializes it if necessary. It is thread-safe and ensures that only one
//instance of the object exists at any given time.
GumInterceptor *
gum_interceptor_obtain (void)
{
  GumInterceptor * interceptor;

  g_mutex_lock (&_gum_interceptor_lock);

#ifndef GUM_DIET
  if (_the_interceptor != NULL)
  {
    interceptor = GUM_INTERCEPTOR (g_object_ref (_the_interceptor));
  }
  else
  {
    _the_interceptor = g_object_new (GUM_TYPE_INTERCEPTOR, NULL);
    g_object_weak_ref (G_OBJECT (_the_interceptor),
        the_interceptor_weak_notify, NULL);

    interceptor = _the_interceptor;
  }
#else
  if (_the_interceptor != NULL)
  {
    interceptor = gum_object_ref (_the_interceptor);
  }
  else
  {
    _the_interceptor = g_new0 (GumInterceptor, 1);
    _the_interceptor->parent.ref_count = 1;
    _the_interceptor->parent.finalize = gum_interceptor_finalize;
    gum_interceptor_init (_the_interceptor);

    interceptor = _the_interceptor;
  }
#endif

  g_mutex_unlock (&_gum_interceptor_lock);

  return interceptor;
}

#ifndef GUM_DIET



// This function is used to reset the static _the_interceptor variable to NULL
//when the GumInterceptor object it refers to is destroyed. It should be called as
//a weak notify callback for that object.
static void
the_interceptor_weak_notify (gpointer data,
                             GObject * where_the_object_was)
{
  g_mutex_lock (&_gum_interceptor_lock);

  g_assert (_the_interceptor == (GumInterceptor *) where_the_object_was);
  _the_interceptor = NULL;

  g_mutex_unlock (&_gum_interceptor_lock);
}

#endif



// This function is used to attach a GumInvocationListener to the given
//address in order to be able to monitor and intercept calls made on it. It
//returns GUM_ATTACH_OK if successful, or one of several error codes depending on
//the situation (e.g. wrong signature, policy violation etc.).
GumAttachReturn
gum_interceptor_attach (GumInterceptor * self,
                        gpointer function_address,
                        GumInvocationListener * listener,
                        gpointer listener_function_data)
{
  GumAttachReturn result = GUM_ATTACH_OK;
  GumFunctionContext * function_ctx;
  GumInstrumentationError error;

  gum_interceptor_ignore_current_thread (self);
  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  self->current_transaction.is_dirty = TRUE;

  function_address = gum_interceptor_resolve (self, function_address);

  function_ctx = gum_interceptor_instrument (self, GUM_INTERCEPTOR_TYPE_DEFAULT,
      function_address, &error);

  if (function_ctx == NULL)
    goto instrumentation_error;

  if (gum_function_context_has_listener (function_ctx, listener))
    goto already_attached;

  gum_function_context_add_listener (function_ctx, listener,
      listener_function_data);

  goto beach;

instrumentation_error:
  {
    switch (error)
    {
      case GUM_INSTRUMENTATION_ERROR_WRONG_SIGNATURE:
        result = GUM_ATTACH_WRONG_SIGNATURE;
        break;
      case GUM_INSTRUMENTATION_ERROR_POLICY_VIOLATION:
        result = GUM_ATTACH_POLICY_VIOLATION;
        break;
      case GUM_INSTRUMENTATION_ERROR_WRONG_TYPE:
        result = GUM_ATTACH_WRONG_TYPE;
        break;
      default:
        g_assert_not_reached ();
    }
    goto beach;
  }
already_attached:
  {
    result = GUM_ATTACH_ALREADY_ATTACHED;
    goto beach;
  }
beach:
  {
    gum_interceptor_transaction_end (&self->current_transaction);
    GUM_INTERCEPTOR_UNLOCK (self);
    gum_interceptor_unignore_current_thread (self);

    return result;
  }
}



//This function detaches the given listener from GumInterceptor, removing it
//from any functions that were previously attached to it. It also removes all data
//associated with this listener for any threads currently being intercepted. This
//is done by acquiring a lock on the gum_interceptor_thread_contexts table and
//then iterating through each thread context and forgetting the listener's
//associated data. Finally, transactions are created as necessary to remove
//references of this listener from GumFunctionContext objects and unreferencing
//them when finished.
void
gum_interceptor_detach (GumInterceptor * self,
                        GumInvocationListener * listener)
{
  GHashTableIter iter;
  gpointer key, value;

  gum_interceptor_ignore_current_thread (self);
  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  self->current_transaction.is_dirty = TRUE;

  g_hash_table_iter_init (&iter, self->function_by_address);
  while (g_hash_table_iter_next (&iter, NULL, &value))
  {
    GumFunctionContext * function_ctx = value;

    if (gum_function_context_has_listener (function_ctx, listener))
    {
      gum_function_context_remove_listener (function_ctx, listener);

      gum_interceptor_transaction_schedule_destroy (&self->current_transaction,
          function_ctx,
#ifndef GUM_DIET
          g_object_unref, g_object_ref (listener)
#else
          gum_object_unref, gum_object_ref (listener)
#endif
      );

      if (gum_function_context_is_empty (function_ctx))
      {
        g_hash_table_iter_remove (&iter);
      }
    }
  }

  gum_spinlock_acquire (&gum_interceptor_thread_context_lock);
  g_hash_table_iter_init (&iter, gum_interceptor_thread_contexts);
  while (g_hash_table_iter_next (&iter, &key, NULL))
  {
    InterceptorThreadContext * thread_ctx = key;

    interceptor_thread_context_forget_listener_data (thread_ctx, listener);
  }
  gum_spinlock_release (&gum_interceptor_thread_context_lock);

  gum_interceptor_transaction_end (&self->current_transaction);
  GUM_INTERCEPTOR_UNLOCK (self);
  gum_interceptor_unignore_current_thread (self);
}



// gum_interceptor_replace() is a function used to replace the original
//function at the given address with a new replacement function. It takes in four
//parameters, including self (the interceptor instance), and returns an integer
//that indicates success or failure of the operation. The other three parameters
//are: 
// 1) function_address - The address of the original function to be
//replaced; 
// 2) replacement_function - The address of the new replacement
//function; 
// 3) replacement_data - Any data required for use by the replacement
//functions; 
// 4) original_function - A pointer which will store any information
//about the original functions after it has been replaced.
GumReplaceReturn
gum_interceptor_replace (GumInterceptor * self,
                         gpointer function_address,
                         gpointer replacement_function,
                         gpointer replacement_data,
                         gpointer * original_function)
{
  return gum_interceptor_replace_with_type (self, GUM_INTERCEPTOR_TYPE_DEFAULT,
      function_address, replacement_function, replacement_data,
      original_function);
}



// GumReplaceReturn is a function that replaces a given function at the
//specified address with a replacement, and also returns the original function. It
//is used in interception scenarios to replace existing functions with custom
//implementations.
GumReplaceReturn
gum_interceptor_replace_fast (GumInterceptor * self,
                              gpointer function_address,
                              gpointer replacement_function,
                              gpointer * original_function)
{
  return gum_interceptor_replace_with_type (self, GUM_INTERCEPTOR_TYPE_FAST,
      function_address, replacement_function, NULL,
      original_function);
}



//This function replaces a given function address with a new
//replacement_function and passes in the optional parameter of replacement_data.
//The original function is returned if the user supplies an original_function
//pointer, otherwise it will be NULL. If instrumentation fails for any reason,
//then GUM_REPLACE will return an appropriate error code. If the provided function
//has already been replaced, GUM_REPLACE will return GUM_REPLACE_ALREADY_REPLACED.
static GumReplaceReturn
gum_interceptor_replace_with_type (GumInterceptor * self,
                                   GumInterceptorType type,
                                   gpointer function_address,
                                   gpointer replacement_function,
                                   gpointer replacement_data,
                                   gpointer * original_function)
{
  GumReplaceReturn result = GUM_REPLACE_OK;
  GumFunctionContext * function_ctx;
  GumInstrumentationError error;

  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  self->current_transaction.is_dirty = TRUE;

  function_address = gum_interceptor_resolve (self, function_address);

  function_ctx =
      gum_interceptor_instrument (self, type, function_address, &error);

  if (function_ctx == NULL)
    goto instrumentation_error;

  if (function_ctx->replacement_function != NULL)
    goto already_replaced;

  function_ctx->replacement_data = replacement_data;
  function_ctx->replacement_function = replacement_function;

  if (original_function != NULL)
    *original_function = function_ctx->on_invoke_trampoline;

  goto beach;

instrumentation_error:
  {
    switch (error)
    {
      case GUM_INSTRUMENTATION_ERROR_WRONG_SIGNATURE:
        result = GUM_REPLACE_WRONG_SIGNATURE;
        break;
      case GUM_INSTRUMENTATION_ERROR_POLICY_VIOLATION:
        result = GUM_REPLACE_POLICY_VIOLATION;
        break;
      case GUM_INSTRUMENTATION_ERROR_WRONG_TYPE:
        result = GUM_REPLACE_WRONG_TYPE;
        break;
      default:
        g_assert_not_reached ();
    }
    goto beach;
  }
already_replaced:
  {
    result = GUM_REPLACE_ALREADY_REPLACED;
    goto beach;
  }
beach:
  {
    gum_interceptor_transaction_end (&self->current_transaction);
    GUM_INTERCEPTOR_UNLOCK (self);

    return result;
  }
}



// This function is used to revert an interception of a given function address
//back to its original state. It begins by locking the GumInterceptor object,
//starting a transaction and setting it as dirty. Then it resolves the provided
//function address and checks if there is an existing GumFunctionContext
//associated with it. If one exists, then the replacement_function and
//replacement_data are set to NULL before checking if there are any other
//functions in that context - if not, then they are removed from the hash table
//before ending the transaction and unlocking the GumInterceptor object.
void
gum_interceptor_revert (GumInterceptor * self,
                        gpointer function_address)
{
  GumFunctionContext * function_ctx;

  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  self->current_transaction.is_dirty = TRUE;

  function_address = gum_interceptor_resolve (self, function_address);

  function_ctx = (GumFunctionContext *) g_hash_table_lookup (
      self->function_by_address, function_address);
  if (function_ctx == NULL)
    goto beach;

  function_ctx->replacement_function = NULL;
  function_ctx->replacement_data = NULL;

  if (gum_function_context_is_empty (function_ctx))
  {
    g_hash_table_remove (self->function_by_address, function_address);
  }

beach:
  gum_interceptor_transaction_end (&self->current_transaction);
  GUM_INTERCEPTOR_UNLOCK (self);
}



//This function begins a new transaction for the GumInterceptor object, by
//acquiring a lock and then calling gum_interceptor_transaction_begin. The purpose
//of this is to ensure that any changes made to interceptors are atomic and
//isolated from other parts of the program.
void
gum_interceptor_begin_transaction (GumInterceptor * self)
{
  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  GUM_INTERCEPTOR_UNLOCK (self);
}



// gum_interceptor_end_transaction is used to close the current transaction on
//a GumInterceptor object. It ensures that any hooks added or removed during the
//transaction are applied, and re-enables interception for any functions affected
//by the transaction.
void
gum_interceptor_end_transaction (GumInterceptor * self)
{
  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_end (&self->current_transaction);
  GUM_INTERCEPTOR_UNLOCK (self);
}



// This function flushes the current transaction in GumInterceptor. It is used
//to reset any changes made to the interceptor, and returns a boolean value
//depending on whether or not the flush was successful.
gboolean
gum_interceptor_flush (GumInterceptor * self)
{
  gboolean flushed = FALSE;

  GUM_INTERCEPTOR_LOCK (self);

  if (self->current_transaction.level == 0)
  {
    gum_interceptor_transaction_begin (&self->current_transaction);
    gum_interceptor_transaction_end (&self->current_transaction);

    flushed =
        g_queue_is_empty (self->current_transaction.pending_destroy_tasks);
  }

  GUM_INTERCEPTOR_UNLOCK (self);

  return flushed;
}



// This function retrieves the current invocation context of a GumInterceptor.
//It first gets the InterceptorThreadContext, then peeks at the top of the
//GumInvocationStackEntry and returns that entry's invocation context if it
//exists, otherwise it returns NULL.
GumInvocationContext *
gum_interceptor_get_current_invocation (void)
{
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStackEntry * entry;

  interceptor_ctx = get_interceptor_thread_context ();
  entry = gum_invocation_stack_peek_top (interceptor_ctx->stack);
  if (entry == NULL)
    return NULL;

  return &entry->invocation_context;
}



// This function retrieves the current GumInvocationStack associated with the
//calling thread. If no stack is found, an empty stack is returned instead.
GumInvocationStack *
gum_interceptor_get_current_stack (void)
{
  InterceptorThreadContext * context;

  context = g_private_get (&gum_interceptor_context_private);
  if (context == NULL)
    return &_gum_interceptor_empty_stack;

  return context->stack;
}



// This function allows the current thread to be ignored by the
//GumInterceptor, so that any interception calls will not affect it. The
//ignore_level of the InterceptorThreadContext is incremented to indicate that
//this thread should be ignored.
void
gum_interceptor_ignore_current_thread (GumInterceptor * self)
{
  InterceptorThreadContext * interceptor_ctx;

  interceptor_ctx = get_interceptor_thread_context ();
  interceptor_ctx->ignore_level++;
}



// This function decreases the ignore level of the current thread in a
//GumInterceptor context. This allows for any intercepted functions called by this
//thread to be monitored and handled as expected.
void
gum_interceptor_unignore_current_thread (GumInterceptor * self)
{
  InterceptorThreadContext * interceptor_ctx;

  interceptor_ctx = get_interceptor_thread_context ();
  interceptor_ctx->ignore_level--;
}



// This function is used to decrement the ignore level of the current thread
//in GumInterceptor. It allows for ignoring specific threads, and returns a
//boolean value indicating whether or not it was successful.
gboolean
gum_interceptor_maybe_unignore_current_thread (GumInterceptor * self)
{
  InterceptorThreadContext * interceptor_ctx;

  interceptor_ctx = get_interceptor_thread_context ();
  if (interceptor_ctx->ignore_level <= 0)
    return FALSE;

  interceptor_ctx->ignore_level--;
  return TRUE;
}



// This function sets the thread ID of the current GumInterceptor instance to
//the ID of the currently running thread. This allows it to ignore any other
//threads that may be running in the same process, ensuring that only actions
//taken by this specific thread are monitored.
void
gum_interceptor_ignore_other_threads (GumInterceptor * self)
{
  self->selected_thread_id = gum_process_get_current_thread_id ();
}



// This function is used to reset the GumInterceptor's selected_thread_id back
//to 0, which indicates that all threads should be considered for interception. It
//is called when the current thread ID no longer needs to be given special
//treatment.
void
gum_interceptor_unignore_other_threads (GumInterceptor * self)
{
  g_assert (self->selected_thread_id == gum_process_get_current_thread_id ());
  self->selected_thread_id = 0;
}



//This function iterates through a GumInvocationStack and searches for an
//entry whose on_leave_trampoline address is equal to the return_address passed as
//parameter. If such an entry exists, it returns its caller_ret_addr; otherwise,
//it returns the original return address.
gpointer
gum_invocation_stack_translate (GumInvocationStack * self,
                                gpointer return_address)
{
  guint i;

  for (i = 0; i != self->len; i++)
  {
    GumInvocationStackEntry * entry;

    entry = &g_array_index (self, GumInvocationStackEntry, i);
    if (entry->function_ctx->on_leave_trampoline == return_address)
      return entry->caller_ret_addr;
  }

  return return_address;
}



// gum_interceptor_save() is a function that stores the current invocation
//state of the GumInterceptor in the given parameter 'state'. It does this by
//setting 'state' to equal the length of GumInterceptor's stack. This allows for
//tracking and restoring different states when needed.
void
gum_interceptor_save (GumInvocationState * state)
{
  *state = gum_interceptor_get_current_stack ()->len;
}



//This function restores the GumInvocationStack to its state prior to a call
//by decrementing the trampoline_usage_counter of all entries added since then and
//setting the size of the stack back to its original value.
void
gum_interceptor_restore (GumInvocationState * state)
{
  GumInvocationStack * stack;
  guint old_depth, new_depth, i;

  stack = gum_interceptor_get_current_stack ();

  old_depth = *state;
  new_depth = stack->len;
  if (new_depth == old_depth)
    return;

  for (i = old_depth; i != new_depth; i++)
  {
    GumInvocationStackEntry * entry;

    entry = &g_array_index (stack, GumInvocationStackEntry, i);

    g_atomic_int_dec_and_test (&entry->function_ctx->trampoline_usage_counter);
  }

  g_array_set_size (stack, old_depth);
}



// This function retrieves the return address of the top caller in an
//invocation stack by using gum_interceptor_get_current_stack() to get a pointer
//to the current stack, checking if it is empty and, if not, returning the last
//entry's caller ret addr.
gpointer
_gum_interceptor_peek_top_caller_return_address (void)
{
  GumInvocationStack * stack;
  GumInvocationStackEntry * entry;

  stack = gum_interceptor_get_current_stack ();
  if (stack->len == 0)
    return NULL;

  entry = &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);

  return entry->caller_ret_addr;
}



// This function is used to translate the top return address from an
//interception trampoline back to the original caller's return address. It helps
//ensure that when a call leaves an intercepted function, it goes back to where it
//was originally intended.
gpointer
_gum_interceptor_translate_top_return_address (gpointer return_address)
{
  GumInvocationStack * stack;
  GumInvocationStackEntry * entry;

  stack = gum_interceptor_get_current_stack ();
  if (stack->len == 0)
    goto fallback;

  entry = &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);
  if (entry->function_ctx->on_leave_trampoline != return_address)
    goto fallback;

  return entry->caller_ret_addr;

fallback:
  return return_address;
}



//This function is used to instrument a given function address using the
//GumInterceptorType and returns a new GumFunctionContext. If the given type does
//not match an existing context, it will try to create a trampoline for that
//address. Otherwise, it will return GUM_INSTRUMENTATION_ERROR if policy violation
//or wrong signature occurs.
static GumFunctionContext *
gum_interceptor_instrument (GumInterceptor * self,
                            GumInterceptorType type,
                            gpointer function_address,
                            GumInstrumentationError * error)
{
  GumFunctionContext * ctx;

  *error = GUM_INSTRUMENTATION_ERROR_NONE;

  ctx = (GumFunctionContext *) g_hash_table_lookup (self->function_by_address,
      function_address);

  if (ctx != NULL)
  {
    if (ctx->type != type)
    {
      *error = GUM_INSTRUMENTATION_ERROR_WRONG_TYPE;
      return NULL;
    }
    return ctx;
  }

  if (self->backend == NULL)
  {
    self->backend =
        _gum_interceptor_backend_create (&self->mutex, &self->allocator);
  }

  ctx = gum_function_context_new (self, function_address, type);

  if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_REQUIRED)
  {
    if (!_gum_interceptor_backend_claim_grafted_trampoline (self->backend, ctx))
      goto policy_violation;
  }
  else
  {
    if (!_gum_interceptor_backend_create_trampoline (self->backend, ctx))
      goto wrong_signature;
  }

  g_hash_table_insert (self->function_by_address, function_address, ctx);

  gum_interceptor_transaction_schedule_update (&self->current_transaction, ctx,
      gum_interceptor_activate);

  return ctx;

policy_violation:
  {
    *error = GUM_INSTRUMENTATION_ERROR_POLICY_VIOLATION;
    goto propagate_error;
  }
wrong_signature:
  {
    *error = GUM_INSTRUMENTATION_ERROR_WRONG_SIGNATURE;
    goto propagate_error;
  }
propagate_error:
  {
    gum_function_context_finalize (ctx);

    return NULL;
  }
}



//This function activates a trampoline for the given context and prologue. It
//is important to ensure that the context has not been destroyed before
//activation, so it guarantees safe execution of the code by checking if it has
//been destroyed or not.
static void
gum_interceptor_activate (GumInterceptor * self,
                          GumFunctionContext * ctx,
                          gpointer prologue)
{
  if (ctx->destroyed)
    return;

  g_assert (!ctx->activated);
  ctx->activated = TRUE;

  _gum_interceptor_backend_activate_trampoline (self->backend, ctx,
      prologue);
}



// This function deactivates a previously activated GumFunctionContext. It
//sets the 'activated' flag to FALSE and calls the backend's
//_gum_interceptor_backend_deactivate_trampoline() method which is responsible for
//restoring the original prologue of the code block being intercepted.
static void
gum_interceptor_deactivate (GumInterceptor * self,
                            GumFunctionContext * ctx,
                            gpointer prologue)
{
  GumInterceptorBackend * backend = self->backend;

  g_assert (ctx->activated);
  ctx->activated = FALSE;

  _gum_interceptor_backend_deactivate_trampoline (backend, ctx, prologue);
}



// This function initializes a GumInterceptorTransaction struct by setting the
//is_dirty and level fields to false, creating empty queues for pending destroy
//tasks and pending update tasks, and assigning the provided interceptor to the
//transaction.
static void
gum_interceptor_transaction_init (GumInterceptorTransaction * transaction,
                                  GumInterceptor * interceptor)
{
  transaction->is_dirty = FALSE;
  transaction->level = 0;
  transaction->pending_destroy_tasks = g_queue_new ();
  transaction->pending_update_tasks = g_hash_table_new_full (
      NULL, NULL, NULL, (GDestroyNotify) g_array_unref);

  transaction->interceptor = interceptor;
}



// This function frees a GumInterceptorTransaction object by unreferencing its
//pending_update_tasks hash table, and then iterating through the
//pending_destroy_tasks queue and calling each task's notify callback before
//freeing it.
static void
gum_interceptor_transaction_destroy (GumInterceptorTransaction * transaction)
{
  GumDestroyTask * task;

  g_hash_table_unref (transaction->pending_update_tasks);

  while ((task = g_queue_pop_head (transaction->pending_destroy_tasks)) != NULL)
  {
    task->notify (task->data);

    g_slice_free (GumDestroyTask, task);
  }
  g_queue_free (transaction->pending_destroy_tasks);
}

static void
gum_interceptor_transaction_begin (GumInterceptorTransaction * self)
{
  self->level++;
}

static void
gum_interceptor_transaction_end (GumInterceptorTransaction * self)
{
  GumInterceptor * interceptor = self->interceptor;
  GumInterceptorTransaction transaction_copy;
  GList * addresses, * cur;

  self->level--;
  if (self->level > 0)
    return;

  if (!self->is_dirty)
    return;

  gum_interceptor_ignore_current_thread (interceptor);

  gum_code_allocator_commit (&interceptor->allocator);

  if (g_queue_is_empty (self->pending_destroy_tasks) &&
      g_hash_table_size (self->pending_update_tasks) == 0)
  {
    interceptor->current_transaction.is_dirty = FALSE;
    goto no_changes;
  }

  transaction_copy = interceptor->current_transaction;
  self = &transaction_copy;
  gum_interceptor_transaction_init (&interceptor->current_transaction,
      interceptor);

  addresses = g_hash_table_get_keys (self->pending_update_tasks);
  addresses = g_list_sort (addresses, gum_page_address_compare);

  if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_REQUIRED)
  {
    for (cur = addresses; cur != NULL; cur = cur->next)
    {
      gpointer target_page = cur->data;
      GArray * pending;
      guint i;

      pending = g_hash_table_lookup (self->pending_update_tasks, target_page);
      g_assert (pending != NULL);

      for (i = 0; i != pending->len; i++)
      {
        GumUpdateTask * update;

        update = &g_array_index (pending, GumUpdateTask, i);

        update->func (interceptor, update->ctx,
            _gum_interceptor_backend_get_function_address (update->ctx));
      }
    }
  }
  else
  {
    guint page_size;
    gboolean rwx_supported, code_segment_supported;

    page_size = gum_query_page_size ();

    rwx_supported = gum_query_is_rwx_supported ();
    code_segment_supported = gum_code_segment_is_supported ();

    if (rwx_supported || !code_segment_supported)
    {
      GumPageProtection protection;
      GumSuspendOperation suspend_op = { 0, G_QUEUE_INIT };

      protection = rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW;

      if (!rwx_supported)
      {
        suspend_op.current_thread_id = gum_process_get_current_thread_id ();
        gum_process_enumerate_threads (gum_maybe_suspend_thread, &suspend_op);
      }

      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        gpointer target_page = cur->data;

        gum_mprotect (target_page, page_size, protection);
      }

      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        gpointer target_page = cur->data;
        GArray * pending;
        guint i;

        pending = g_hash_table_lookup (self->pending_update_tasks,
            target_page);
        g_assert (pending != NULL);

        for (i = 0; i != pending->len; i++)
        {
          GumUpdateTask * update;

          update = &g_array_index (pending, GumUpdateTask, i);

          update->func (interceptor, update->ctx,
              _gum_interceptor_backend_get_function_address (update->ctx));
        }
      }

      if (!rwx_supported)
      {
        for (cur = addresses; cur != NULL; cur = cur->next)
        {
          gpointer target_page = cur->data;

          gum_mprotect (target_page, page_size, GUM_PAGE_RX);
        }
      }

      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        gpointer target_page = cur->data;

        gum_clear_cache (target_page, page_size);
      }

      if (!rwx_supported)
      {
        gpointer raw_id;

        while (
            (raw_id = g_queue_pop_tail (&suspend_op.suspended_threads)) != NULL)
        {
          gum_thread_resume (GPOINTER_TO_SIZE (raw_id), NULL);
        }
      }
    }
    else
    {
      guint num_pages;
      GumCodeSegment * segment;
      guint8 * source_page, * current_page;
      gsize source_offset;

      num_pages = g_hash_table_size (self->pending_update_tasks);
      segment = gum_code_segment_new (num_pages * page_size, NULL);

      source_page = gum_code_segment_get_address (segment);

      current_page = source_page;
      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        guint8 * target_page = cur->data;

        memcpy (current_page, target_page, page_size);

        current_page += page_size;
      }

      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        guint8 * target_page = cur->data;
        GArray * pending;
        guint i;

        pending = g_hash_table_lookup (self->pending_update_tasks,
            target_page);
        g_assert (pending != NULL);

        for (i = 0; i != pending->len; i++)
        {
          GumUpdateTask * update;

          update = &g_array_index (pending, GumUpdateTask, i);

          update->func (interceptor, update->ctx, source_page +
              ((guint8 *) _gum_interceptor_backend_get_function_address (
                  update->ctx) - target_page));
        }

        source_page += page_size;
      }

      gum_code_segment_realize (segment);

      source_offset = 0;
      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        gpointer target_page = cur->data;

        gum_code_segment_map (segment, source_offset, page_size, target_page);

        gum_clear_cache (target_page, page_size);

        source_offset += page_size;
      }

      gum_code_segment_free (segment);
    }
  }

  g_list_free (addresses);

  {
    GumDestroyTask * task;

    while ((task = g_queue_pop_head (self->pending_destroy_tasks)) != NULL)
    {
      if (task->ctx->trampoline_usage_counter == 0)
      {
        GUM_INTERCEPTOR_UNLOCK (interceptor);
        task->notify (task->data);
        GUM_INTERCEPTOR_LOCK (interceptor);

        g_slice_free (GumDestroyTask, task);
      }
      else
      {
        interceptor->current_transaction.is_dirty = TRUE;
        g_queue_push_tail (
            interceptor->current_transaction.pending_destroy_tasks, task);
      }
    }
  }

  gum_interceptor_transaction_destroy (self);

no_changes:
  gum_interceptor_unignore_current_thread (interceptor);
}



//This function is used to suspend a thread identified by its id. It loops
//through all existing threads and checks if the current thread matches the target
//one. If it does, then that thread is suspended and added to a queue of suspended
//threads.
static gboolean
gum_maybe_suspend_thread (const GumThreadDetails * details,
                          gpointer user_data)
{
  GumSuspendOperation * op = user_data;

  if (details->id == op->current_thread_id)
    goto skip;

  if (!gum_thread_suspend (details->id, NULL))
    goto skip;

  g_queue_push_tail (&op->suspended_threads, GSIZE_TO_POINTER (details->id));

skip:
  return TRUE;
}



//This function schedules a destroy task to be executed at the end of an
//interceptor transaction. It stores the GumFunctionContext, GDestroyNotify and
//data pointer in a GumDestroyTask struct which is then pushed to the tail of
//self->pending_destroy_tasks queue.
static void
gum_interceptor_transaction_schedule_destroy (GumInterceptorTransaction * self,
                                              GumFunctionContext * ctx,
                                              GDestroyNotify notify,
                                              gpointer data)
{
  GumDestroyTask * task;

  task = g_slice_new (GumDestroyTask);
  task->ctx = ctx;
  task->notify = notify;
  task->data = data;

  g_queue_push_tail (self->pending_destroy_tasks, task);
}



// This function schedules an update task for a given GumFunctionContext. It
//stores the start and end pages of the context in a hash table, mapping them to
//an array of GumUpdateTasks that need to be executed on those pages.
static void
gum_interceptor_transaction_schedule_update (GumInterceptorTransaction * self,
                                             GumFunctionContext * ctx,
                                             GumUpdateTaskFunc func)
{
  guint8 * function_address;
  gpointer start_page, end_page;
  GArray * pending;
  GumUpdateTask update;

  function_address = _gum_interceptor_backend_get_function_address (ctx);

  start_page = gum_page_address_from_pointer (function_address);
  end_page = gum_page_address_from_pointer (function_address +
      ctx->overwritten_prologue_len - 1);

  pending = g_hash_table_lookup (self->pending_update_tasks, start_page);
  if (pending == NULL)
  {
    pending = g_array_new (FALSE, FALSE, sizeof (GumUpdateTask));
    g_hash_table_insert (self->pending_update_tasks, start_page, pending);
  }

  update.ctx = ctx;
  update.func = func;
  g_array_append_val (pending, update);

  if (end_page != start_page)
  {
    pending = g_hash_table_lookup (self->pending_update_tasks, end_page);
    if (pending == NULL)
    {
      pending = g_array_new (FALSE, FALSE, sizeof (GumUpdateTask));
      g_hash_table_insert (self->pending_update_tasks, end_page, pending);
    }
  }
}



//This function creates a new GumFunctionContext object, which is used by the
//GumInterceptor library to store information about a particular function. It sets
//the pointer address and type of the function as well as an interceptor for that
//function and initializes an empty array for listener entries.
static GumFunctionContext *
gum_function_context_new (GumInterceptor * interceptor,
                          gpointer function_address,
                          GumInterceptorType type)
{
  GumFunctionContext * ctx;

  ctx = g_slice_new0 (GumFunctionContext);
  ctx->function_address = function_address;
  ctx->type = type;
  ctx->listener_entries =
      g_ptr_array_new_full (1, (GDestroyNotify) listener_entry_free);
  ctx->interceptor = interceptor;

  return ctx;
}



// This function is responsible for freeing a GumFunctionContext struct and
//all the associated memory. It checks that the trampoline_slice field of the
//struct is NULL before proceeding to unreferencing any listener entries and
//finally freeing the slice containing the struct itself.
static void
gum_function_context_finalize (GumFunctionContext * function_ctx)
{
  g_assert (function_ctx->trampoline_slice == NULL);

  g_ptr_array_unref (
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries));

  g_slice_free (GumFunctionContext, function_ctx);
}



//gum_function_context_destroy is a function used to properly clean up and
//free resources associated with the GumFunctionContext object. It takes in the
//context as its parameter, checks if it has already been destroyed, deactivates
//it if needed, then schedules its destruction. Finally,
//gum_function_context_perform_destroy is called to complete the destruction
//process.
static void
gum_function_context_destroy (GumFunctionContext * function_ctx)
{
  GumInterceptorTransaction * transaction =
      &function_ctx->interceptor->current_transaction;

  g_assert (!function_ctx->destroyed);
  function_ctx->destroyed = TRUE;

  if (function_ctx->activated)
  {
    gum_interceptor_transaction_schedule_update (transaction, function_ctx,
        gum_interceptor_deactivate);
  }

  gum_interceptor_transaction_schedule_destroy (transaction, function_ctx,
      (GDestroyNotify) gum_function_context_perform_destroy, function_ctx);
}



// This function is responsible for destroying a GumFunctionContext object. It
//calls _gum_interceptor_backend_destroy_trampoline to remove the trampoline
//associated with the context, and then calls gum_function_context_finalize to
//perform final cleanup of the object before it is destroyed.
static void
gum_function_context_perform_destroy (GumFunctionContext * function_ctx)
{
  _gum_interceptor_backend_destroy_trampoline (
      function_ctx->interceptor->backend, function_ctx);

  gum_function_context_finalize (function_ctx);
}



//This function checks if the provided GumFunctionContext is empty by checking
//for a replacement_function and any taken listener slots. Returns TRUE if both
//are absent, FALSE otherwise.
static gboolean
gum_function_context_is_empty (GumFunctionContext * function_ctx)
{
  if (function_ctx->replacement_function != NULL)
    return FALSE;

  return gum_function_context_find_taken_listener_slot (function_ctx) == NULL;
}



//This function adds a listener entry to the given GumFunctionContext and
//updates the function_ctx->listener_entries array. It also sets the
//has_on_leave_listener flag if needed.
static void
gum_function_context_add_listener (GumFunctionContext * function_ctx,
                                   GumInvocationListener * listener,
                                   gpointer function_data)
{
  ListenerEntry * entry;
  GPtrArray * old_entries, * new_entries;
  guint i;

  entry = g_slice_new (ListenerEntry);
#ifndef GUM_DIET
  entry->listener_interface = GUM_INVOCATION_LISTENER_GET_IFACE (listener);
#endif
  entry->listener_instance = listener;
  entry->function_data = function_data;

  old_entries =
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
  new_entries = g_ptr_array_new_full (old_entries->len + 1,
      (GDestroyNotify) listener_entry_free);
  for (i = 0; i != old_entries->len; i++)
  {
    ListenerEntry * old_entry = g_ptr_array_index (old_entries, i);
    if (old_entry != NULL)
      g_ptr_array_add (new_entries, g_slice_dup (ListenerEntry, old_entry));
  }
  g_ptr_array_add (new_entries, entry);

  g_atomic_pointer_set (&function_ctx->listener_entries, new_entries);
  gum_interceptor_transaction_schedule_destroy (
      &function_ctx->interceptor->current_transaction, function_ctx,
      (GDestroyNotify) g_ptr_array_unref, old_entries);

  if (entry->listener_interface->on_leave != NULL)
  {
    function_ctx->has_on_leave_listener = TRUE;
  }
}



//listener_entry_free() is a function that frees the memory allocated for an
//instance of ListenerEntry struct. It takes an argument of pointer to
//ListenerEntry and returns nothing.
static void
listener_entry_free (ListenerEntry * entry)
{
  g_slice_free (ListenerEntry, entry);
}



// This function removes a GumInvocationListener from the list of listeners
//for a specific GumFunctionContext. It first finds the listener in the list, then
//frees its associated ListenerEntry, and finally sets its slot to NULL. Finally
//it checks if any other listeners have an on_leave method and updates
//has_on_leave_listener accordingly.
static void
gum_function_context_remove_listener (GumFunctionContext * function_ctx,
                                      GumInvocationListener * listener)
{
  ListenerEntry ** slot;
  gboolean has_on_leave_listener;
  GPtrArray * listener_entries;
  guint i;

  slot = gum_function_context_find_listener (function_ctx, listener);
  g_assert (slot != NULL);
  listener_entry_free (*slot);
  *slot = NULL;

  has_on_leave_listener = FALSE;
  listener_entries =
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry * entry = g_ptr_array_index (listener_entries, i);
    if (entry != NULL && entry->listener_interface->on_leave != NULL)
    {
      has_on_leave_listener = TRUE;
      break;
    }
  }
  function_ctx->has_on_leave_listener = has_on_leave_listener;
}



//This function checks whether a given GumInvocationListener is associated
//with the GumFunctionContext. It returns TRUE if the listener exists, otherwise
//FALSE.
static gboolean
gum_function_context_has_listener (GumFunctionContext * function_ctx,
                                   GumInvocationListener * listener)
{
  return gum_function_context_find_listener (function_ctx, listener) != NULL;
}



//This function searches for the GumInvocationListener instance in the
//GPtrArray of ListenerEntries and returns a pointer to the slot containing that
//instance. It is used to retrieve information from a given listener associated
//with a GumFunctionContext.
static ListenerEntry **
gum_function_context_find_listener (GumFunctionContext * function_ctx,
                                    GumInvocationListener * listener)
{
  GPtrArray * listener_entries;
  guint i;

  listener_entries =
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry ** slot = (ListenerEntry **)
        &g_ptr_array_index (listener_entries, i);
    if (*slot != NULL && (*slot)->listener_instance == listener)
      return slot;
  }

  return NULL;
}



//This function looks for a free slot in the listener_entries pointer array of
//the given GumFunctionContext and returns it if found. If no empty slot is found,
//NULL is returned.
static ListenerEntry **
gum_function_context_find_taken_listener_slot (
    GumFunctionContext * function_ctx)
{
  GPtrArray * listener_entries;
  guint i;

  listener_entries =
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry ** slot = (ListenerEntry **)
        &g_ptr_array_index (listener_entries, i);
    if (*slot != NULL)
      return slot;
  }

  return NULL;
}

void
_gum_function_context_begin_invocation (GumFunctionContext * function_ctx,
                                        GumCpuContext * cpu_context,
                                        gpointer * caller_ret_addr,
                                        gpointer * next_hop)
{
  GumInterceptor * interceptor;
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStack * stack;
  GumInvocationStackEntry * stack_entry;
  GumInvocationContext * invocation_ctx = NULL;
  gint system_error;
  gboolean invoke_listeners = TRUE;
  gboolean will_trap_on_leave;

  g_atomic_int_inc (&function_ctx->trampoline_usage_counter);

  interceptor = function_ctx->interceptor;

#ifdef HAVE_WINDOWS
  system_error = gum_thread_get_system_error ();
#endif

  if (gum_tls_key_get_value (gum_interceptor_guard_key) == interceptor)
  {
    *next_hop = function_ctx->on_invoke_trampoline;
    goto bypass;
  }
  gum_tls_key_set_value (gum_interceptor_guard_key, interceptor);

  interceptor_ctx = get_interceptor_thread_context ();
  stack = interceptor_ctx->stack;

  stack_entry = gum_invocation_stack_peek_top (stack);
  if (stack_entry != NULL &&
      stack_entry->calling_replacement &&
      gum_strip_code_pointer (GUM_FUNCPTR_TO_POINTER (
          stack_entry->invocation_context.function)) ==
          function_ctx->function_address)
  {
    gum_tls_key_set_value (gum_interceptor_guard_key, NULL);
    *next_hop = function_ctx->on_invoke_trampoline;
    goto bypass;
  }

#ifndef HAVE_WINDOWS
  system_error = gum_thread_get_system_error ();
#endif

  if (interceptor->selected_thread_id != 0)
  {
    invoke_listeners =
        gum_process_get_current_thread_id () == interceptor->selected_thread_id;
  }

  if (invoke_listeners)
  {
    invoke_listeners = (interceptor_ctx->ignore_level <= 0);
  }

  will_trap_on_leave = function_ctx->replacement_function != NULL ||
      (invoke_listeners && function_ctx->has_on_leave_listener);
  if (will_trap_on_leave)
  {
    stack_entry = gum_invocation_stack_push (stack, function_ctx,
        *caller_ret_addr);
    invocation_ctx = &stack_entry->invocation_context;
  }
  else if (invoke_listeners)
  {
    stack_entry = gum_invocation_stack_push (stack, function_ctx,
        function_ctx->function_address);
    invocation_ctx = &stack_entry->invocation_context;
  }

  if (invocation_ctx != NULL)
    invocation_ctx->system_error = system_error;

  gum_function_context_fixup_cpu_context (function_ctx, cpu_context);

  if (invoke_listeners)
  {
    GPtrArray * listener_entries;
    guint i;

    invocation_ctx->cpu_context = cpu_context;
    invocation_ctx->backend = &interceptor_ctx->listener_backend;

    listener_entries =
        (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
    for (i = 0; i != listener_entries->len; i++)
    {
      ListenerEntry * listener_entry;
      ListenerInvocationState state;

      listener_entry = g_ptr_array_index (listener_entries, i);
      if (listener_entry == NULL)
        continue;

      state.point_cut = GUM_POINT_ENTER;
      state.entry = listener_entry;
      state.interceptor_ctx = interceptor_ctx;
      state.invocation_data = stack_entry->listener_invocation_data[i];
      invocation_ctx->backend->data = &state;

#ifndef GUM_DIET
      if (listener_entry->listener_interface->on_enter != NULL)
      {
        listener_entry->listener_interface->on_enter (
            listener_entry->listener_instance, invocation_ctx);
      }
#else
      gum_invocation_listener_on_enter (listener_entry->listener_instance,
          invocation_ctx);
#endif
    }

    system_error = invocation_ctx->system_error;
  }

  if (!will_trap_on_leave && invoke_listeners)
  {
    gum_invocation_stack_pop (interceptor_ctx->stack);
  }

  gum_thread_set_system_error (system_error);

  gum_tls_key_set_value (gum_interceptor_guard_key, NULL);

  if (will_trap_on_leave)
  {
    *caller_ret_addr = function_ctx->on_leave_trampoline;
  }

  if (function_ctx->replacement_function != NULL)
  {
    stack_entry->calling_replacement = TRUE;
    stack_entry->cpu_context = *cpu_context;
    stack_entry->original_system_error = system_error;
    invocation_ctx->cpu_context = &stack_entry->cpu_context;
    invocation_ctx->backend = &interceptor_ctx->replacement_backend;
    invocation_ctx->backend->data = function_ctx->replacement_data;

    *next_hop = function_ctx->replacement_function;
  }
  else
  {
    *next_hop = function_ctx->on_invoke_trampoline;
  }

  if (!will_trap_on_leave)
  {
    g_atomic_int_dec_and_test (&function_ctx->trampoline_usage_counter);
  }

  return;

bypass:
  g_atomic_int_dec_and_test (&function_ctx->trampoline_usage_counter);
}



//This function is part of the GumInterceptor API and is used to end an
//invocation (i.e. after a function call has been intercepted) and notify any
//registered listeners that the invocation has ended. It takes in a
//GumFunctionContext, GumCpuContext, and pointer to the next hop address as
//parameters. It sets system error based on platform it's running on, fixes up CPU
//context if needed, notifies all registered listeners with 'on_leave' callback
//about the ending of an invocation before finally popping off from stack entry
//and decrementing trampoline usage counter.
void
_gum_function_context_end_invocation (GumFunctionContext * function_ctx,
                                      GumCpuContext * cpu_context,
                                      gpointer * next_hop)
{
  gint system_error;
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStackEntry * stack_entry;
  GumInvocationContext * invocation_ctx;
  GPtrArray * listener_entries;
  guint i;

#ifdef HAVE_WINDOWS
  system_error = gum_thread_get_system_error ();
#endif

  gum_tls_key_set_value (gum_interceptor_guard_key, function_ctx->interceptor);

#ifndef HAVE_WINDOWS
  system_error = gum_thread_get_system_error ();
#endif

  interceptor_ctx = get_interceptor_thread_context ();

  stack_entry = gum_invocation_stack_peek_top (interceptor_ctx->stack);
  *next_hop = gum_sign_code_pointer (stack_entry->caller_ret_addr);

  invocation_ctx = &stack_entry->invocation_context;
  invocation_ctx->cpu_context = cpu_context;
  if (stack_entry->calling_replacement &&
      invocation_ctx->system_error != stack_entry->original_system_error)
  {
    system_error = invocation_ctx->system_error;
  }
  else
  {
    invocation_ctx->system_error = system_error;
  }
  invocation_ctx->backend = &interceptor_ctx->listener_backend;

  gum_function_context_fixup_cpu_context (function_ctx, cpu_context);

  listener_entries =
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry * listener_entry;
    ListenerInvocationState state;

    listener_entry = g_ptr_array_index (listener_entries, i);
    if (listener_entry == NULL)
      continue;

    state.point_cut = GUM_POINT_LEAVE;
    state.entry = listener_entry;
    state.interceptor_ctx = interceptor_ctx;
    state.invocation_data = stack_entry->listener_invocation_data[i];
    invocation_ctx->backend->data = &state;

#ifndef GUM_DIET
    if (listener_entry->listener_interface->on_leave != NULL)
    {
      listener_entry->listener_interface->on_leave (
          listener_entry->listener_instance, invocation_ctx);
    }
#else
    gum_invocation_listener_on_leave (listener_entry->listener_instance,
        invocation_ctx);
#endif
  }

  gum_thread_set_system_error (invocation_ctx->system_error);

  gum_invocation_stack_pop (interceptor_ctx->stack);

  gum_tls_key_set_value (gum_interceptor_guard_key, NULL);

  g_atomic_int_dec_and_test (&function_ctx->trampoline_usage_counter);
}



//This function is used to fix up the program counter (PC) of a GumCpuContext
//structure for use with a given GumFunctionContext. It sets the PC value to be
//equal to the address of the function associated with that context, adjusting it
//as needed based on architecture.
static void
gum_function_context_fixup_cpu_context (GumFunctionContext * function_ctx,
                                        GumCpuContext * cpu_context)
{
  gsize pc;

  pc = GPOINTER_TO_SIZE (function_ctx->function_address);
#ifdef HAVE_ARM
  pc &= ~1;
#endif

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  cpu_context->eip = pc;
# else
  cpu_context->rip = pc;
# endif
#elif defined (HAVE_ARM)
  cpu_context->pc = pc;
#elif defined (HAVE_ARM64)
  cpu_context->pc = pc;
#elif defined (HAVE_MIPS)
  cpu_context->pc = pc;
#else
# error Unsupported architecture
#endif
}



//This function gets the InterceptorThreadContext from a private thread-local
//storage and creates it if it doesn't exist yet. It then adds this context to the
//global hash table of contexts, using a spinlock for synchronization. Finally, it
//returns the context.
static InterceptorThreadContext *
get_interceptor_thread_context (void)
{
  InterceptorThreadContext * context;

  context = g_private_get (&gum_interceptor_context_private);
  if (context == NULL)
  {
    context = interceptor_thread_context_new ();

    gum_spinlock_acquire (&gum_interceptor_thread_context_lock);
    g_hash_table_add (gum_interceptor_thread_contexts, context);
    gum_spinlock_release (&gum_interceptor_thread_context_lock);

    g_private_set (&gum_interceptor_context_private, context);
  }

  return context;
}



//This function removes an InterceptorThreadContext from the
//gum_interceptor_thread_contexts hash table and releases the associated spinlock.
//This ensures that any resources associated with this context are freed up for
//other uses.
static void
release_interceptor_thread_context (InterceptorThreadContext * context)
{
  if (gum_interceptor_thread_contexts == NULL)
    return;

  gum_spinlock_acquire (&gum_interceptor_thread_context_lock);
  g_hash_table_remove (gum_interceptor_thread_contexts, context);
  gum_spinlock_release (&gum_interceptor_thread_context_lock);
}



//This function returns the point cut associated with a given invocation
//context. The returned value is of type GumPointCut, which is an enumeration that
//indicates when interception should occur (e.g before or after a call). This
//allows listeners to be registered at different points in the execution flow and
//helps ensure that they are triggered at the correct time.
static GumPointCut
gum_interceptor_invocation_get_listener_point_cut (
    GumInvocationContext * context)
{
  return ((ListenerInvocationState *) context->backend->data)->point_cut;
}

static GumPointCut
gum_interceptor_invocation_get_replacement_point_cut (
    GumInvocationContext * context)
{
  return GUM_POINT_ENTER;
}



/* This function retrieves the thread ID of the current process. It is used to
//identify which thread an invocation context belongs to and can be used in
//applications that need to track multiple threads at once. */
static GumThreadId
gum_interceptor_invocation_get_thread_id (GumInvocationContext * context)
{
  return gum_process_get_current_thread_id ();
}



/* This function returns the depth of the current thread's
//GumInvocationContext stack, which is used to keep track of recursive calls. The
//higher the depth value, the deeper into a call stack we are. */
static guint
gum_interceptor_invocation_get_depth (GumInvocationContext * context)
{
  InterceptorThreadContext * interceptor_ctx =
      (InterceptorThreadContext *) context->backend->state;

  return interceptor_ctx->stack->len - 1;
}



This function retrieves thread-specific data associated with a given listener
//instance from the GumInvocationContext. It is used to store and retrieve
//information specific to each listener during an invocation, such as the return
//value of a called function or any other user-defined data that needs to be
//shared between listeners for this particular call.
static gpointer
gum_interceptor_invocation_get_listener_thread_data (
    GumInvocationContext * context,
    gsize required_size)
{
  ListenerInvocationState * data =
      (ListenerInvocationState *) context->backend->data;

  return interceptor_thread_context_get_listener_data (data->interceptor_ctx,
      data->entry->listener_instance, required_size);
}



// This function retrieves the listener function data associated with a
//GumInvocationContext object. It is used to access user-defined data related to
//an intercepted function call.
static gpointer
gum_interceptor_invocation_get_listener_function_data (
    GumInvocationContext * context)
{
  return ((ListenerInvocationState *)
      context->backend->data)->entry->function_data;
}



// This function is used to retrieve a pointer to the ListenerInvocationState
//data associated with an InvocationContext. It ensures that the size of the
//requested data does not exceed GUM_MAX_LISTENER_DATA and returns NULL if it
//does. The goal is to ensure that only valid listener invocation state data can
//be accessed.
static gpointer
gum_interceptor_invocation_get_listener_invocation_data (
    GumInvocationContext * context,
    gsize required_size)
{
  ListenerInvocationState * data;

  data = (ListenerInvocationState *) context->backend->data;

  if (required_size > GUM_MAX_LISTENER_DATA)
    return NULL;

  return data->invocation_data;
}



//This function retrieves the replacement data associated with an invocation
//context. This allows access to the data stored in GumInvocationContext's
//backend, which is used to specify a replacement function when intercepting code.
static gpointer
gum_interceptor_invocation_get_replacement_data (GumInvocationContext * context)
{
  return context->backend->data;
}

static const GumInvocationBackend
gum_interceptor_listener_invocation_backend =
{
  gum_interceptor_invocation_get_listener_point_cut,

  gum_interceptor_invocation_get_thread_id,
  gum_interceptor_invocation_get_depth,

  gum_interceptor_invocation_get_listener_thread_data,
  gum_interceptor_invocation_get_listener_function_data,
  gum_interceptor_invocation_get_listener_invocation_data,

  NULL,

  NULL,
  NULL
};

static const GumInvocationBackend
gum_interceptor_replacement_invocation_backend =
{
  gum_interceptor_invocation_get_replacement_point_cut,

  gum_interceptor_invocation_get_thread_id,
  gum_interceptor_invocation_get_depth,

  NULL,
  NULL,
  NULL,

  gum_interceptor_invocation_get_replacement_data,

  NULL,
  NULL
};



//This function creates a new InterceptorThreadContext and initializes it with
//default values for its fields. The goal of this function is to provide an
//initialized context that can be used by other functions in the GumInterceptor
//API.
static InterceptorThreadContext *
interceptor_thread_context_new (void)
{
  InterceptorThreadContext * context;

  context = g_slice_new0 (InterceptorThreadContext);

  gum_memcpy (&context->listener_backend,
      &gum_interceptor_listener_invocation_backend,
      sizeof (GumInvocationBackend));
  gum_memcpy (&context->replacement_backend,
      &gum_interceptor_replacement_invocation_backend,
      sizeof (GumInvocationBackend));
  context->listener_backend.state = context;
  context->replacement_backend.state = context;

  context->ignore_level = 0;

  context->stack = g_array_sized_new (FALSE, TRUE,
      sizeof (GumInvocationStackEntry), GUM_MAX_CALL_DEPTH);

  context->listener_data_slots = g_array_sized_new (FALSE, TRUE,
      sizeof (ListenerDataSlot), GUM_MAX_LISTENERS_PER_FUNCTION);

  return context;
}



//This function destroys an InterceptorThreadContext object by freeing its
//listener_data_slots array, stack array and then the context itself.
static void
interceptor_thread_context_destroy (InterceptorThreadContext * context)
{
  g_array_free (context->listener_data_slots, TRUE);

  g_array_free (context->stack, TRUE);

  g_slice_free (InterceptorThreadContext, context);
}



//This function is used to get listener data from an InterceptorThreadContext
//object. It checks if the required size of the data does not exceed
//GUM_MAX_LISTENER_DATA and iterates through a ListenerDataSlot array for the
//InterceptorThreadContext object to find an available slot with no owner or one
//that belongs to the given listener. If a new slot needs to be created, it sets
//its owner as the given listener and returns its data.
static gpointer
interceptor_thread_context_get_listener_data (InterceptorThreadContext * self,
                                              GumInvocationListener * listener,
                                              gsize required_size)
{
  guint i;
  ListenerDataSlot * available_slot = NULL;

  if (required_size > GUM_MAX_LISTENER_DATA)
    return NULL;

  for (i = 0; i != self->listener_data_slots->len; i++)
  {
    ListenerDataSlot * slot;

    slot = &g_array_index (self->listener_data_slots, ListenerDataSlot, i);
    if (slot->owner == listener)
      return slot->data;
    else if (slot->owner == NULL)
      available_slot = slot;
  }

  if (available_slot == NULL)
  {
    g_array_set_size (self->listener_data_slots,
        self->listener_data_slots->len + 1);
    available_slot = &g_array_index (self->listener_data_slots,
        ListenerDataSlot, self->listener_data_slots->len - 1);
  }
  else
  {
    gum_memset (available_slot->data, 0, sizeof (available_slot->data));
  }

  available_slot->owner = listener;

  return available_slot->data;
}



/*This function is used to forget the listener data associated with a given
//InterceptorThreadContext. It iterates over the self->listener_data_slots array
//and sets the owner of that slot to NULL if it matches the provided listener.*/
static void
interceptor_thread_context_forget_listener_data (
    InterceptorThreadContext * self,
    GumInvocationListener * listener)
{
  guint i;

  for (i = 0; i != self->listener_data_slots->len; i++)
  {
    ListenerDataSlot * slot;

    slot = &g_array_index (self->listener_data_slots, ListenerDataSlot, i);
    if (slot->owner == listener)
    {
      slot->owner = NULL;
      return;
    }
  }
}



//This function pushes a GumInvocationStackEntry to the end of a given stack,
//initializing it with the provided GumFunctionContext and caller_ret_addr. It
//also sets up the invocation context associated with this entry. The return value
//is a pointer to this newly created entry.
static GumInvocationStackEntry *
gum_invocation_stack_push (GumInvocationStack * stack,
                           GumFunctionContext * function_ctx,
                           gpointer caller_ret_addr)
{
  GumInvocationStackEntry * entry;
  GumInvocationContext * ctx;

  g_array_set_size (stack, stack->len + 1);
  entry = (GumInvocationStackEntry *)
      &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);
  entry->function_ctx = function_ctx;
  entry->caller_ret_addr = caller_ret_addr;

  ctx = &entry->invocation_context;
  ctx->function = gum_sign_code_pointer (function_ctx->function_address);

  ctx->backend = NULL;

  return entry;
}



// This function pops the last invocation stack entry from an array of
//GumInvocationStackEntries and returns its caller return address.
static gpointer
gum_invocation_stack_pop (GumInvocationStack * stack)
{
  GumInvocationStackEntry * entry;
  gpointer caller_ret_addr;

  entry = (GumInvocationStackEntry *)
      &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);
  caller_ret_addr = entry->caller_ret_addr;
  g_array_set_size (stack, stack->len - 1);

  return caller_ret_addr;
}



// gum_invocation_stack_peek_top() is a function that retrieves the top
//element in the GumInvocationStack array. It returns a pointer to a
//GumInvocationStackEntry which contains information about the current invocation
//context, or NULL if stack->len is 0 (indicating an empty array).
static GumInvocationStackEntry *
gum_invocation_stack_peek_top (GumInvocationStack * stack)
{
  if (stack->len == 0)
    return NULL;

  return &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);
}



//This function resolves a given address, stripping any code pointer and
//ensuring the code is readable. It then follows any grafted branches if the
//process's code signing policy requires it. If a target is found, it will call
//itself recursively to resolve that target before returning the original address
//or resolved target.
static gpointer
gum_interceptor_resolve (GumInterceptor * self,
                         gpointer address)
{
  address = gum_strip_code_pointer (address);

  if (!gum_interceptor_has (self, address))
  {
    const gsize max_redirect_size = 16;
    gpointer target;

    gum_ensure_code_readable (address, max_redirect_size);

    /* Avoid following grafted branches. */
    if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_REQUIRED)
      return address;

    target = _gum_interceptor_backend_resolve_redirect (self->backend,
        address);
    if (target != NULL)
      return gum_interceptor_resolve (self, target);
  }

  return address;
}



// This function checks if a given function address is present in the
//GumInterceptor object's 'function_by_address' hash table. It returns TRUE if the
//function address is found, FALSE otherwise.
static gboolean
gum_interceptor_has (GumInterceptor * self,
                     gpointer function_address)
{
  return g_hash_table_lookup (self->function_by_address,
      function_address) != NULL;
}



//This function takes a pointer as an argument and returns the start address
//of the page it is contained in. It achieves this by taking the pointer value,
//converting it to size and then masking off the lower bits corresponding to the
//page size.
static gpointer
gum_page_address_from_pointer (gpointer ptr)
{
  return GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (ptr) & ~((gsize) gum_query_page_size () - 1));
}



/* Compares two page addresses, a and b, returning a negative value if a is
//less than b, zero if they are equal or positive value if a is greater than b.
//This function can be used to sort an array of page addresses. */
static gint
gum_page_address_compare (gconstpointer a,
                          gconstpointer b)
{
  return GPOINTER_TO_SIZE (a) - GPOINTER_TO_SIZE (b);
}
