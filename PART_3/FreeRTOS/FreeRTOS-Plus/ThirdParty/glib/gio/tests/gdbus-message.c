/* GLib testing framework examples and tests
 *
 * Copyright (C) 2008-2010 Red Hat, Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 */

#include <locale.h>
#include <gio/gio.h>

/* ---------------------------------------------------------------------------------------------------- */

static void
on_notify_locked (GObject    *object,
                  GParamSpec *pspec,
                  gpointer    user_data)
{
  gint *count = user_data;
  *count += 1;
}

static void
message_lock (void)
{
  GDBusMessage *m;
  gint count;

  count = 0;
  m = g_dbus_message_new ();
  g_signal_connect (m,
                    "notify::locked",
                    G_CALLBACK (on_notify_locked),
                    &count);
  g_assert (!g_dbus_message_get_locked (m));
  g_dbus_message_lock (m);
  g_assert (g_dbus_message_get_locked (m));
  g_assert_cmpint (count, ==, 1);
  g_dbus_message_lock (m);
  g_assert (g_dbus_message_get_locked (m));
  g_assert_cmpint (count, ==, 1);

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "*Attempted to modify a locked message*");
  g_dbus_message_set_serial (m, 42);
  g_test_assert_expected_messages ();

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "*Attempted to modify a locked message*");
  g_dbus_message_set_byte_order (m, G_DBUS_MESSAGE_BYTE_ORDER_BIG_ENDIAN);
  g_test_assert_expected_messages ();

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "*Attempted to modify a locked message*");
  g_dbus_message_set_message_type (m, G_DBUS_MESSAGE_TYPE_METHOD_CALL);
  g_test_assert_expected_messages ();

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "*Attempted to modify a locked message*");
  g_dbus_message_set_flags (m, G_DBUS_MESSAGE_FLAGS_NONE);
  g_test_assert_expected_messages ();

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "*Attempted to modify a locked message*");
  g_dbus_message_set_body (m, NULL);
  g_test_assert_expected_messages ();

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "*Attempted to modify a locked message*");
  g_dbus_message_set_header (m, 0, NULL);
  g_test_assert_expected_messages ();

  g_object_unref (m);
}

/* ---------------------------------------------------------------------------------------------------- */

static void
message_copy (void)
{
  GDBusMessage *m;
  GDBusMessage *copy;
  GError *error;
  guchar *m_headers;
  guchar *copy_headers;
  guint n;

  m = g_dbus_message_new_method_call ("org.example.Name",
                                      "/org/example/Object",
                                      "org.example.Interface",
                                      "Method");
  g_dbus_message_set_serial (m, 42);
  g_dbus_message_set_byte_order (m, G_DBUS_MESSAGE_BYTE_ORDER_BIG_ENDIAN);

  error = NULL;
  copy = g_dbus_message_copy (m, &error);
  g_assert_no_error (error);
  g_assert (G_IS_DBUS_MESSAGE (copy));
  g_assert (m != copy);
  g_assert_cmpint (G_OBJECT (m)->ref_count, ==, 1);
  g_assert_cmpint (G_OBJECT (copy)->ref_count, ==, 1);

  g_assert_cmpint (g_dbus_message_get_serial (copy), ==, g_dbus_message_get_serial (m));
  g_assert_cmpint (g_dbus_message_get_byte_order (copy), ==, g_dbus_message_get_byte_order (m));
  g_assert_cmpint (g_dbus_message_get_flags (copy), ==, g_dbus_message_get_flags (m));
  g_assert_cmpint (g_dbus_message_get_message_type (copy), ==, g_dbus_message_get_message_type (m));
  m_headers = g_dbus_message_get_header_fields (m);
  copy_headers = g_dbus_message_get_header_fields (copy);
  g_assert (m_headers != NULL);
  g_assert (copy_headers != NULL);
  for (n = 0; m_headers[n] != 0; n++)
    {
      GVariant *m_val;
      GVariant *copy_val;
      m_val = g_dbus_message_get_header (m, m_headers[n]);
      copy_val = g_dbus_message_get_header (m, m_headers[n]);
      g_assert (m_val != NULL);
      g_assert (copy_val != NULL);
      g_assert_cmpvariant (m_val, copy_val);
    }
  g_assert_cmpint (n, >, 0); /* make sure we actually compared headers etc. */
  g_assert_cmpint (copy_headers[n], ==, 0);
  g_free (m_headers);
  g_free (copy_headers);

  g_object_unref (copy);
  g_object_unref (m);
}

/* ---------------------------------------------------------------------------------------------------- */

/* Test g_dbus_message_bytes_needed() returns correct results for a variety of
 * arbitrary binary inputs.*/
static void
message_bytes_needed (void)
{
  const struct
    {
      const guint8 blob[16];
      gssize expected_bytes_needed;
    }
  vectors[] =
    {
      /* Little endian with header rounding */
      { { 'l', 0, 0, 1,  /* endianness, message type, flags, protocol version */
          50, 0, 0, 0,  /* body length */
          1, 0, 0, 0,  /* message serial */
          7, 0, 0, 0  /* header length */}, 74 },
      /* Little endian without header rounding */
      { { 'l', 0, 0, 1,  /* endianness, message type, flags, protocol version */
          50, 0, 0, 0,  /* body length */
          1, 0, 0, 0,  /* message serial */
          8, 0, 0, 0  /* header length */}, 74 },
      /* Big endian with header rounding */
      { { 'B', 0, 0, 1,  /* endianness, message type, flags, protocol version */
          0, 0, 0, 50,  /* body length */
          0, 0, 0, 1,  /* message serial */
          0, 0, 0, 7  /* header length */}, 74 },
      /* Big endian without header rounding */
      { { 'B', 0, 0, 1,  /* endianness, message type, flags, protocol version */
          0, 0, 0, 50,  /* body length */
          0, 0, 0, 1,  /* message serial */
          0, 0, 0, 8  /* header length */}, 74 },
      /* Invalid endianness */
      { { '!', 0, 0, 1,  /* endianness, message type, flags, protocol version */
          0, 0, 0, 50,  /* body length */
          0, 0, 0, 1,  /* message serial */
          0, 0, 0, 8  /* header length */}, -1 },
      /* Oversized */
      { { 'l', 0, 0, 1,  /* endianness, message type, flags, protocol version */
          0, 0, 0, 0x08,  /* body length (128MiB) */
          1, 0, 0, 0,  /* message serial */
          7, 0, 0, 0  /* header length */}, -1 },
    };
  gsize i;

  for (i = 0; i < G_N_ELEMENTS (vectors); i++)
    {
      gssize bytes_needed;
      GError *local_error = NULL;

      g_test_message ("Vector: %" G_GSIZE_FORMAT, i);

      bytes_needed = g_dbus_message_bytes_needed ((guchar *) vectors[i].blob,
                                                  G_N_ELEMENTS (vectors[i].blob),
                                                  &local_error);

      if (vectors[i].expected_bytes_needed < 0)
        g_assert_error (local_error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
      else
        g_assert_no_error (local_error);
      g_assert_cmpint (bytes_needed, ==, vectors[i].expected_bytes_needed);

      g_clear_error (&local_error);
    }
}

/* ---------------------------------------------------------------------------------------------------- */

int
main (int   argc,
      char *argv[])
{
  setlocale (LC_ALL, "C");

  g_test_init (&argc, &argv, G_TEST_OPTION_ISOLATE_DIRS, NULL);

  g_test_add_func ("/gdbus/message/lock", message_lock);
  g_test_add_func ("/gdbus/message/copy", message_copy);
  g_test_add_func ("/gdbus/message/bytes-needed", message_bytes_needed);

  return g_test_run ();
}
