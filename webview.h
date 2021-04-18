/*
 * MIT License
 *
 * Copyright (c) 2017 Serge Zaitsev
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef WEBVIEW_H
#define WEBVIEW_H

#ifndef WEBVIEW_API
#define WEBVIEW_API extern
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void *webview_t;

// Creates a new webview instance. If debug is non-zero - developer tools will
// be enabled (if the platform supports them). Window parameter can be a
// pointer to the native window handle. If it's non-null - then child WebView
// is embedded into the given parent window. Otherwise a new window is created.
// Depending on the platform, a GtkWindow, NSWindow or HWND pointer can be
// passed here.
WEBVIEW_API webview_t webview_create(int debug, void *window);

// Destroys a webview and closes the native window.
WEBVIEW_API void webview_destroy(webview_t w);

// Runs the main loop until it's terminated. After this function exits - you
// must destroy the webview.
WEBVIEW_API void webview_run(webview_t w);

// Stops the main loop. It is safe to call this function from another other
// background thread.
WEBVIEW_API void webview_terminate(webview_t w);

// Posts a function to be executed on the main thread. You normally do not need
// to call this function, unless you want to tweak the native window.
WEBVIEW_API void
webview_dispatch(webview_t w, void (*fn)(webview_t w, void *arg), void *arg);

// Returns a native window handle pointer. When using GTK backend the pointer
// is GtkWindow pointer, when using Cocoa backend the pointer is NSWindow
// pointer, when using Win32 backend the pointer is HWND pointer.
WEBVIEW_API void *webview_get_window(webview_t w);

// Updates the title of the native window. Must be called from the UI thread.
WEBVIEW_API void webview_set_title(webview_t w, const char *title);

// Window size hints
#define WEBVIEW_HINT_NONE 0  // Width and height are default size
#define WEBVIEW_HINT_MIN 1   // Width and height are minimum bounds
#define WEBVIEW_HINT_MAX 2   // Width and height are maximum bounds
#define WEBVIEW_HINT_FIXED 3 // Window size can not be changed by a user
// Updates native window size. See WEBVIEW_HINT constants.
WEBVIEW_API void webview_set_size(webview_t w, int width, int height,
                                  int hints);

// Navigates webview to the given URL. URL may be a data URI, i.e.
// "data:text/text,<html>...</html>". It is often ok not to url-encode it
// properly, webview will re-encode it for you.
WEBVIEW_API void webview_navigate(webview_t w, const char *url);

// Injects JavaScript code at the initialization of the new page. Every time
// the webview will open a the new page - this initialization code will be
// executed. It is guaranteed that code is executed before window.onload.
WEBVIEW_API void webview_init(webview_t w, const char *js);

// Evaluates arbitrary JavaScript code. Evaluation happens asynchronously, also
// the result of the expression is ignored. Use RPC bindings if you want to
// receive notifications about the results of the evaluation.
WEBVIEW_API void webview_eval(webview_t w, const char *js);

// Binds a native C callback so that it will appear under the given name as a
// global JavaScript function. Internally it uses webview_init(). Callback
// receives a request string and a user-provided argument pointer. Request
// string is a JSON array of all the arguments passed to the JavaScript
// function.
WEBVIEW_API void webview_bind(webview_t w, const char *name,
                              void (*fn)(const char *seq, const char *req,
                                         void *arg),
                              void *arg);

// Allows to return a value from the native binding. Original request pointer
// must be provided to help internal RPC engine match requests with responses.
// If status is zero - result is expected to be a valid JSON result value.
// If status is not zero - result is an error JSON object.
WEBVIEW_API void webview_return(webview_t w, const char *seq, int status,
                                const char *result);

// Take Screenshot and save image file into path.
// Only osx yet.
WEBVIEW_API void webview_screenshot(webview_t w, const char *path);

// Show custom context-menu.
// Only osx yet.
WEBVIEW_API void webview_custom_context_menu(webview_t w, const char *message);

// Set not allowed host.
// Only osx yet.
WEBVIEW_API void webview_set_not_allowed_host(webview_t w, const char *host);

#ifdef __cplusplus
}
#endif

#ifndef WEBVIEW_HEADER

#if !defined(WEBVIEW_GTK) && !defined(WEBVIEW_COCOA) && !defined(WEBVIEW_EDGE)
#if defined(__linux__)
#define WEBVIEW_GTK
#elif defined(__APPLE__)
#define WEBVIEW_COCOA
#elif defined(_WIN32)
#define WEBVIEW_EDGE
#else
#error "please, specify webview backend"
#endif
#endif

#include <atomic>
#include <functional>
#include <future>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include <cstring>

namespace webview {
using dispatch_fn_t = std::function<void()>;

// Convert ASCII hex digit to a nibble (four bits, 0 - 15).
//
// Use unsigned to avoid signed overflow UB.
static inline unsigned char hex2nibble(unsigned char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  } else if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  } else if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  return 0;
}

// Convert ASCII hex string (two characters) to byte.
//
// E.g., "0B" => 0x0B, "af" => 0xAF.
static inline char hex2char(const char *p) {
  return hex2nibble(p[0]) * 16 + hex2nibble(p[1]);
}

inline std::string url_encode(const std::string s) {
  std::string encoded;
  for (unsigned int i = 0; i < s.length(); i++) {
    auto c = s[i];
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      encoded = encoded + c;
    } else {
      char hex[4];
      snprintf(hex, sizeof(hex), "%%%02x", c);
      encoded = encoded + hex;
    }
  }
  return encoded;
}

inline std::string url_decode(const std::string st) {
  std::string decoded;
  const char *s = st.c_str();
  size_t length = strlen(s);
  for (unsigned int i = 0; i < length; i++) {
    if (s[i] == '%') {
      decoded.push_back(hex2char(s + i + 1));
      i = i + 2;
    } else if (s[i] == '+') {
      decoded.push_back(' ');
    } else {
      decoded.push_back(s[i]);
    }
  }
  return decoded;
}

inline std::string html_from_uri(const std::string s) {
  if (s.substr(0, 15) == "data:text/html,") {
    return url_decode(s.substr(15));
  }
  return "";
}

inline int json_parse_c(const char *s, size_t sz, const char *key, size_t keysz,
                        const char **value, size_t *valuesz) {
  enum {
    JSON_STATE_VALUE,
    JSON_STATE_LITERAL,
    JSON_STATE_STRING,
    JSON_STATE_ESCAPE,
    JSON_STATE_UTF8
  } state = JSON_STATE_VALUE;
  const char *k = NULL;
  int index = 1;
  int depth = 0;
  int utf8_bytes = 0;

  if (key == NULL) {
    index = keysz;
    keysz = 0;
  }

  *value = NULL;
  *valuesz = 0;

  for (; sz > 0; s++, sz--) {
    enum {
      JSON_ACTION_NONE,
      JSON_ACTION_START,
      JSON_ACTION_END,
      JSON_ACTION_START_STRUCT,
      JSON_ACTION_END_STRUCT
    } action = JSON_ACTION_NONE;
    unsigned char c = *s;
    switch (state) {
    case JSON_STATE_VALUE:
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' ||
          c == ':') {
        continue;
      } else if (c == '"') {
        action = JSON_ACTION_START;
        state = JSON_STATE_STRING;
      } else if (c == '{' || c == '[') {
        action = JSON_ACTION_START_STRUCT;
      } else if (c == '}' || c == ']') {
        action = JSON_ACTION_END_STRUCT;
      } else if (c == 't' || c == 'f' || c == 'n' || c == '-' ||
                 (c >= '0' && c <= '9')) {
        action = JSON_ACTION_START;
        state = JSON_STATE_LITERAL;
      } else {
        return -1;
      }
      break;
    case JSON_STATE_LITERAL:
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' ||
          c == ']' || c == '}' || c == ':') {
        state = JSON_STATE_VALUE;
        s--;
        sz++;
        action = JSON_ACTION_END;
      } else if (c < 32 || c > 126) {
        return -1;
      } // fallthrough
    case JSON_STATE_STRING:
      if (c < 32 || (c > 126 && c < 192)) {
        return -1;
      } else if (c == '"') {
        action = JSON_ACTION_END;
        state = JSON_STATE_VALUE;
      } else if (c == '\\') {
        state = JSON_STATE_ESCAPE;
      } else if (c >= 192 && c < 224) {
        utf8_bytes = 1;
        state = JSON_STATE_UTF8;
      } else if (c >= 224 && c < 240) {
        utf8_bytes = 2;
        state = JSON_STATE_UTF8;
      } else if (c >= 240 && c < 247) {
        utf8_bytes = 3;
        state = JSON_STATE_UTF8;
      } else if (c >= 128 && c < 192) {
        return -1;
      }
      break;
    case JSON_STATE_ESCAPE:
      if (c == '"' || c == '\\' || c == '/' || c == 'b' || c == 'f' ||
          c == 'n' || c == 'r' || c == 't' || c == 'u') {
        state = JSON_STATE_STRING;
      } else {
        return -1;
      }
      break;
    case JSON_STATE_UTF8:
      if (c < 128 || c > 191) {
        return -1;
      }
      utf8_bytes--;
      if (utf8_bytes == 0) {
        state = JSON_STATE_STRING;
      }
      break;
    default:
      return -1;
    }

    if (action == JSON_ACTION_END_STRUCT) {
      depth--;
    }

    if (depth == 1) {
      if (action == JSON_ACTION_START || action == JSON_ACTION_START_STRUCT) {
        if (index == 0) {
          *value = s;
        } else if (keysz > 0 && index == 1) {
          k = s;
        } else {
          index--;
        }
      } else if (action == JSON_ACTION_END ||
                 action == JSON_ACTION_END_STRUCT) {
        if (*value != NULL && index == 0) {
          *valuesz = (size_t)(s + 1 - *value);
          return 0;
        } else if (keysz > 0 && k != NULL) {
          if (keysz == (size_t)(s - k - 1) && memcmp(key, k + 1, keysz) == 0) {
            index = 0;
          } else {
            index = 2;
          }
          k = NULL;
        }
      }
    }

    if (action == JSON_ACTION_START_STRUCT) {
      depth++;
    }
  }
  return -1;
}

inline std::string json_escape(std::string s) {
  // TODO: implement
  return '"' + s + '"';
}

inline int json_unescape(const char *s, size_t n, char *out) {
  int r = 0;
  if (*s++ != '"') {
    return -1;
  }
  while (n > 2) {
    char c = *s;
    if (c == '\\') {
      s++;
      n--;
      switch (*s) {
      case 'b':
        c = '\b';
        break;
      case 'f':
        c = '\f';
        break;
      case 'n':
        c = '\n';
        break;
      case 'r':
        c = '\r';
        break;
      case 't':
        c = '\t';
        break;
      case '\\':
        c = '\\';
        break;
      case '/':
        c = '/';
        break;
      case '\"':
        c = '\"';
        break;
      default: // TODO: support unicode decoding
        return -1;
      }
    }
    if (out != NULL) {
      *out++ = c;
    }
    s++;
    n--;
    r++;
  }
  if (*s != '"') {
    return -1;
  }
  if (out != NULL) {
    *out = '\0';
  }
  return r;
}

inline std::string json_parse(const std::string s, const std::string key,
                              const int index) {
  const char *value;
  size_t value_sz;
  if (key == "") {
    json_parse_c(s.c_str(), s.length(), nullptr, index, &value, &value_sz);
  } else {
    json_parse_c(s.c_str(), s.length(), key.c_str(), key.length(), &value,
                 &value_sz);
  }
  if (value != nullptr) {
    if (value[0] != '"') {
      return std::string(value, value_sz);
    }
    int n = json_unescape(value, value_sz, nullptr);
    if (n > 0) {
      char *decoded = new char[n + 1];
      json_unescape(value, value_sz, decoded);
      std::string result(decoded, n);
      delete[] decoded;
      return result;
    }
  }
  return "";
}

} // namespace webview

#if defined(WEBVIEW_GTK)
//
// ====================================================================
//
// This implementation uses webkit2gtk backend. It requires gtk+3.0 and
// webkit2gtk-4.0 libraries. Proper compiler flags can be retrieved via:
//
//   pkg-config --cflags --libs gtk+-3.0 webkit2gtk-4.0
//
// ====================================================================
//
#include <JavaScriptCore/JavaScript.h>
#include <gtk/gtk.h>
#include <webkit2/webkit2.h>

namespace webview {

class gtk_webkit_engine {
public:
  gtk_webkit_engine(bool debug, void *window)
      : m_window(static_cast<GtkWidget *>(window)) {
    gtk_init_check(0, NULL);
    m_window = static_cast<GtkWidget *>(window);
    if (m_window == nullptr) {
      m_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    }
    g_signal_connect(G_OBJECT(m_window), "destroy",
                     G_CALLBACK(+[](GtkWidget *, gpointer arg) {
                       static_cast<gtk_webkit_engine *>(arg)->terminate();
                     }),
                     this);
    // Initialize webview widget
    m_webview = webkit_web_view_new();
    WebKitUserContentManager *manager =
        webkit_web_view_get_user_content_manager(WEBKIT_WEB_VIEW(m_webview));
    g_signal_connect(manager, "script-message-received::external",
                     G_CALLBACK(+[](WebKitUserContentManager *,
                                    WebKitJavascriptResult *r, gpointer arg) {
                       auto *w = static_cast<gtk_webkit_engine *>(arg);
#if WEBKIT_MAJOR_VERSION >= 2 && WEBKIT_MINOR_VERSION >= 22
                       JSCValue *value =
                           webkit_javascript_result_get_js_value(r);
                       char *s = jsc_value_to_string(value);
#else
                       JSGlobalContextRef ctx =
                           webkit_javascript_result_get_global_context(r);
                       JSValueRef value = webkit_javascript_result_get_value(r);
                       JSStringRef js = JSValueToStringCopy(ctx, value, NULL);
                       size_t n = JSStringGetMaximumUTF8CStringSize(js);
                       char *s = g_new(char, n);
                       JSStringGetUTF8CString(js, s, n);
                       JSStringRelease(js);
#endif
                       w->on_message(s);
                       g_free(s);
                     }),
                     this);
    webkit_user_content_manager_register_script_message_handler(manager,
                                                                "external");
    init("window.external={invoke:function(s){window.webkit.messageHandlers."
         "external.postMessage(s);}}");

    gtk_container_add(GTK_CONTAINER(m_window), GTK_WIDGET(m_webview));
    gtk_widget_grab_focus(GTK_WIDGET(m_webview));

    WebKitSettings *settings =
        webkit_web_view_get_settings(WEBKIT_WEB_VIEW(m_webview));
    webkit_settings_set_javascript_can_access_clipboard(settings, true);
    if (debug) {
      webkit_settings_set_enable_write_console_messages_to_stdout(settings,
                                                                  true);
      webkit_settings_set_enable_developer_extras(settings, true);
    }

    gtk_widget_show_all(m_window);
  }
  void *window() { return (void *)m_window; }
  void run() { gtk_main(); }
  void terminate() { gtk_main_quit(); }
  void dispatch(std::function<void()> f) {
    g_idle_add_full(G_PRIORITY_HIGH_IDLE, (GSourceFunc)([](void *f) -> int {
                      (*static_cast<dispatch_fn_t *>(f))();
                      return G_SOURCE_REMOVE;
                    }),
                    new std::function<void()>(f),
                    [](void *f) { delete static_cast<dispatch_fn_t *>(f); });
  }

  void set_title(const std::string title) {
    gtk_window_set_title(GTK_WINDOW(m_window), title.c_str());
  }

  void set_size(int width, int height, int hints) {
    gtk_window_set_resizable(GTK_WINDOW(m_window), hints != WEBVIEW_HINT_FIXED);
    if (hints == WEBVIEW_HINT_NONE) {
      gtk_window_resize(GTK_WINDOW(m_window), width, height);
    } else if (hints == WEBVIEW_HINT_FIXED) {
      gtk_widget_set_size_request(m_window, width, height);
    } else {
      GdkGeometry g;
      g.min_width = g.max_width = width;
      g.min_height = g.max_height = height;
      GdkWindowHints h =
          (hints == WEBVIEW_HINT_MIN ? GDK_HINT_MIN_SIZE : GDK_HINT_MAX_SIZE);
      // This defines either MIN_SIZE, or MAX_SIZE, but not both:
      gtk_window_set_geometry_hints(GTK_WINDOW(m_window), nullptr, &g, h);
    }
  }

  void navigate(const std::string url) {
    webkit_web_view_load_uri(WEBKIT_WEB_VIEW(m_webview), url.c_str());
  }

  void init(const std::string js) {
    WebKitUserContentManager *manager =
        webkit_web_view_get_user_content_manager(WEBKIT_WEB_VIEW(m_webview));
    webkit_user_content_manager_add_script(
        manager, webkit_user_script_new(
                     js.c_str(), WEBKIT_USER_CONTENT_INJECT_TOP_FRAME,
                     WEBKIT_USER_SCRIPT_INJECT_AT_DOCUMENT_START, NULL, NULL));
  }

  void eval(const std::string js) {
    webkit_web_view_run_javascript(WEBKIT_WEB_VIEW(m_webview), js.c_str(), NULL,
                                   NULL, NULL);
  }

  void screenshot(const std::string path) {
    // TODO
  }

  void custom_context_menu(const std::string message) {
    // TODO
  }

  void set_not_allowed_host(const std::string host) {
    // TODO
  }

private:
  virtual void on_message(const std::string msg) = 0;
  GtkWidget *m_window;
  GtkWidget *m_webview;
};

using browser_engine = gtk_webkit_engine;

} // namespace webview

#elif defined(WEBVIEW_COCOA)

//
// ====================================================================
//
// This implementation uses Cocoa WKWebView backend on macOS. It is
// written using ObjC runtime and uses WKWebView class as a browser runtime.
// You should pass "-framework Webkit" flag to the compiler.
//
// ====================================================================
//

#include <CoreGraphics/CoreGraphics.h>
#include <objc/objc-runtime.h>

#define NSBackingStoreBuffered 2

#define NSWindowStyleMaskResizable 8
#define NSWindowStyleMaskMiniaturizable 4
#define NSWindowStyleMaskTitled 1
#define NSWindowStyleMaskClosable 2

#define NSApplicationActivationPolicyRegular 0

#define WKUserScriptInjectionTimeAtDocumentStart 0

#define NSUTF8StringEncoding 4

#define NSPNGFileType 4

#define WKNavigationActionPolicyCancel 0
#define WKNavigationActionPolicyAllow 1

namespace webview {

// Helpers to avoid too much typing
id operator"" _cls(const char *s, std::size_t) { return (id)objc_getClass(s); }
SEL operator"" _sel(const char *s, std::size_t) { return sel_registerName(s); }
id operator"" _str(const char *s, std::size_t) {
  return ((id(*)(id, SEL, const char *))objc_msgSend)(
      "NSString"_cls, "stringWithUTF8String:"_sel, s);
}

class cocoa_wkwebview_engine {
public:
  cocoa_wkwebview_engine(bool debug, void *window) {
    // Application
    id app = ((id(*)(id, SEL))objc_msgSend)("NSApplication"_cls,
                                            "sharedApplication"_sel);
    ((void (*)(id, SEL, long))objc_msgSend)(
        app, "setActivationPolicy:"_sel, NSApplicationActivationPolicyRegular);

    // Delegate
    auto cls =
        objc_allocateClassPair((Class) "NSResponder"_cls, "AppDelegate", 0);
    class_addProtocol(cls, objc_getProtocol("NSTouchBarProvider"));
    class_addProtocol(cls, objc_getProtocol("WKNavigationDelegate"));
    class_addProtocol(cls, objc_getProtocol("WKUIDelegate"));
    class_addMethod(cls, "applicationShouldTerminateAfterLastWindowClosed:"_sel,
                    (IMP)(+[](id, SEL, id) -> BOOL { return 1; }), "c@:@");
    class_addMethod(cls, "userContentController:didReceiveScriptMessage:"_sel,
                    (IMP)(+[](id self, SEL, id, id msg) {
                      auto w =
                          (cocoa_wkwebview_engine *)objc_getAssociatedObject(
                              self, "webview");
                      assert(w);
                      w->on_message(((const char *(*)(id, SEL))objc_msgSend)(
                          ((id(*)(id, SEL))objc_msgSend)(msg, "body"_sel),
                          "UTF8String"_sel));
                    }),
                    "v@:@@");
    class_addMethod(cls, "removeCache:"_sel,
                    (IMP)(+[](id, SEL) {
                      // NSSet *remove_data_types = [WKWebsiteDataStore allWebsiteDataTypes];
                      id remove_data_types = ((id(*)(id, SEL))objc_msgSend)(
                          "WKWebsiteDataStore"_cls, "allWebsiteDataTypes"_sel);
                      // NSDate *date_from = [NSDate dateWithTimeIntervalSince1970:0];
                      id date_from = ((id(*)(id, SEL, double))objc_msgSend)(
                          "NSDate"_cls, "dateWithTimeIntervalSince1970:"_sel, 0);
                      id block = (id)(^() {
                        // do something
                      });
                      // [[WKWebsiteDataStore defaultDataStore] removeDataOfTypes:remove_data_types modifiedSince:date_from completionHandler:^{}];
                      ((void (*)(id, SEL, id, id, id))objc_msgSend)(
                          ((id(*)(id, SEL))objc_msgSend)("WKWebsiteDataStore"_cls, "defaultDataStore"_sel),
                          "removeDataOfTypes:modifiedSince:completionHandler:"_sel,
                          remove_data_types,
                          date_from,
                          block);
                    }),
                    "v@:");
    class_addMethod(cls, "webView:decidePolicyForNavigationAction:decisionHandler:"_sel,
                    (IMP)(+[](id self, SEL, id, id navigation_action, void (^decision_handler)(int)) {
                      auto w =
                          (cocoa_wkwebview_engine *)objc_getAssociatedObject(
                              self, "webview");
                      assert(w);
                      id request = ((id (*)(id, SEL))objc_msgSend)(navigation_action, "request"_sel);
                      id url = ((id (*)(id, SEL))objc_msgSend)(request, "URL"_sel);
                      id url_str = ((id (*)(id, SEL))objc_msgSend)(url, "host"_sel);
                      BOOL not_allowed = ((BOOL (*)(id, SEL, id))objc_msgSend)(url_str,
                          "isEqualToString:"_sel,
                          w->m_host);
                      if (!not_allowed) {
                          decision_handler(WKNavigationActionPolicyAllow);
                      } else {
                          // do something
                          decision_handler(WKNavigationActionPolicyCancel);
                      }
                    }),
                    "v@:@@@");
    class_addMethod(cls, "snapshot:"_sel,
                    (IMP)(+[](id self, SEL) {
                        auto w =
                            (cocoa_wkwebview_engine *)objc_getAssociatedObject(
                                self, "webview");
                        assert(w);
                        CGRect webview_frame = ((CGRect (*)(id, SEL))objc_msgSend_stret)(w->m_webview, "frame"_sel);
                        auto snapshot_configuration = ((id(*)(id, SEL))objc_msgSend)("WKSnapshotConfiguration"_cls, "new"_sel);
                        ((void (*)(id, SEL, CGRect))objc_msgSend)(snapshot_configuration, "setRect:"_sel, webview_frame);
                        ((void (*)(id, SEL, BOOL))objc_msgSend)(snapshot_configuration, "setAfterScreenUpdates:"_sel, 0);

                        id block = (id)(^(id img, CGError err) {
                          if (!err) {
                            // convert image type PNG
                            id data = ((id(*)(id, SEL))objc_msgSend)(img, "TIFFRepresentation"_sel);
                            id bitmapImageRep = ((id(*)(id, SEL, id))objc_msgSend)("NSBitmapImageRep"_cls, "imageRepWithData:"_sel, data);
                            id properties = ((id(*)(id, SEL, id, id))objc_msgSend)(
                                "NSDictionary"_cls, "dictionaryWithObject:forKey:"_sel,
                                ((id(*)(id, SEL, BOOL))objc_msgSend)("NSNumber"_cls, "numberWithBool:"_sel, 1),
                                "NSImageInterlaced"_str);
                            id data_ = ((id(*)(id, SEL, unsigned long, id))objc_msgSend)(bitmapImageRep,
                                "representationUsingType:properties:"_sel,
                                NSPNGFileType,
                                properties);

                            // prepare image file name
                            id now = ((id(*)(id, SEL))objc_msgSend)("NSDate"_cls, "date"_sel);
                            id formatter = ((id(*)(id, SEL))objc_msgSend)(
                                ((id(*)(id, SEL))objc_msgSend)(
                                    "NSDateFormatter"_cls, "alloc"_sel),
                                    "init"_sel);
                            ((void (*)(id, SEL, id))objc_msgSend)(
                                formatter, "setDateFormat:"_sel, "YYYYMMddhhmmss"_str);
                            id img_file_name = ((id(*)(id, SEL, id))objc_msgSend)(
                                ((id(*)(id, SEL, id))objc_msgSend)(
                                    formatter, "stringFromDate:"_sel, now),
                                "stringByAppendingString:"_sel,
                                ".png"_str);
                            ((void (*)(id, SEL))objc_msgSend)(formatter, "release"_sel);
                            // save image
                            ((void (*)(id, SEL, id, BOOL))objc_msgSend)(
                                data_, "writeToFile:atomically:"_sel, img_file_name, 1);
                          }
                        });
                        // take snapshot
                        ((void (*)(id, SEL, id, id))objc_msgSend)(
                            w->m_webview,"takeSnapshotWithConfiguration:completionHandler:"_sel,
                            snapshot_configuration,
                            block
                        );
                    }),
                    "v@:");
    class_addMethod(cls, "webView:runJavaScriptAlertPanelWithMessage:initiatedByFrame:completionHandler:"_sel,
                    (IMP)(+[](id, SEL, id webview_, id message, id, void (^completion_handler)()) {
                      id alert = ((id(*)(id, SEL))objc_msgSend)(
                          ((id(*)(id, SEL))objc_msgSend)("NSAlert"_cls, "alloc"_sel),
                          "init"_sel);
                      ((void (*)(id, SEL, id))objc_msgSend)(
                          alert, "setMessageText:"_sel, message);
                      ((void (*)(id, SEL, id))objc_msgSend)(
                          alert, "setInformativeText:"_sel,
                          ((id (*)(id, SEL))objc_msgSend)(
                              ((id (*)(id, SEL))objc_msgSend)(
                                  webview_, "URL"_sel),
                              "host"_sel));
                      ((void (*)(id, SEL, id))objc_msgSend)(
                          alert, "addButtonWithTitle:"_sel, "Close"_str);
                      ((id (*)(id, SEL))objc_msgSend)(
                          alert, "runModal"_sel);
                      completion_handler();
                    }),
                    "v@:@@@@");
    class_addMethod(cls, "copy_link:"_sel,
                    (IMP)(+[](id self, SEL) {
                      auto w =
                          (cocoa_wkwebview_engine *)objc_getAssociatedObject(
                              self, "webview");
                      assert(w);
                      const char * js = {
                          "var selection = window.getSelection();"
                          "if (selection.rangeCount > 0){"
                          " var tmpElement = document.createElement('input');"
                          " tmpElement.value = selection.getRangeAt(0).startContainer.parentNode.href;"
                          " document.body.appendChild(tmpElement);"
                          " tmpElement.select();"
                          " document.execCommand('copy');"
                          " tmpElement.parentElement.removeChild(tmpElement);"
                          "}"};
                      ((void (*)(id, SEL, id, id))objc_msgSend)(
                          w->m_webview, "evaluateJavaScript:completionHandler:"_sel,
                          ((id(*)(id, SEL, const char *))objc_msgSend)(
                              "NSString"_cls, "stringWithUTF8String:"_sel, js),
                          nullptr);
                    }),
                    "v@:");
    class_addMethod(cls, "copy_text:"_sel,
                    (IMP)(+[](id self, SEL) {
                      auto w =
                          (cocoa_wkwebview_engine *)objc_getAssociatedObject(
                              self, "webview");
                      assert(w);
                      const char * js = {
                          "var selection = window.getSelection();"
                          "if (selection.rangeCount > 0){"
                          " selection.toString();"
                          "}"};
                        id block = (id)(^(id text, CGError err) {
                          if (!err) {
                              ((void (*)(id, SEL))objc_msgSend)(
                                  ((id(*)(id, SEL))objc_msgSend)("NSPasteboard"_cls, "generalPasteboard"_sel),
                                  "clearContents"_sel);
                              ((void (*)(id, SEL, id, id))objc_msgSend)(
                                  ((id(*)(id, SEL))objc_msgSend)("NSPasteboard"_cls, "generalPasteboard"_sel),
                                  "setString:forType:"_sel,
                                  text,
                                  "NSStringPboardType"_str);
                          }
                        });
                      ((void (*)(id, SEL, id, id))objc_msgSend)(
                          w->m_webview, "evaluateJavaScript:completionHandler:"_sel,
                          ((id(*)(id, SEL, const char *))objc_msgSend)(
                              "NSString"_cls, "stringWithUTF8String:"_sel, js),
                          block);
                    }),
                    "v@:");
    class_addMethod(cls, "paste_text:"_sel,
                    (IMP)(+[](id self, SEL) {
                      auto w =
                          (cocoa_wkwebview_engine *)objc_getAssociatedObject(
                              self, "webview");
                      assert(w);
                      id text = ((id (*)(id, SEL, id))objc_msgSend)(
                          ((id(*)(id, SEL))objc_msgSend)("NSPasteboard"_cls, "generalPasteboard"_sel),
                          "stringForType:"_sel,
                          "NSStringPboardType"_str);
                      const char *js_first = {
                          "var element = document.activeElement;"
                          "if (!!element &&"
                          "    (element.tagName == 'INPUT' || element.tagName == 'TEXTAREA')){"
	                      "element.value = element.value.substr(0, element.selectionStart) + '"
                          };
                      const char *text_char = ((const char * (*)(id, SEL))objc_msgSend)(text, "UTF8String"_sel);
                      const char *js_second = {
                          "' + element.value.substr(element.selectionStart);"
                          "}"};
                      id js_nsstring = ((id(*)(id, SEL, const char *))objc_msgSend)(
                              "NSString"_cls, "stringWithUTF8String:"_sel, js_first);
                      js_nsstring = ((id(*)(id, SEL, id))objc_msgSend)(
                              js_nsstring, "stringByAppendingString:"_sel,
                              ((id(*)(id, SEL, const char *))objc_msgSend)(
                                  "NSString"_cls, "stringWithUTF8String:"_sel, text_char));
                      js_nsstring = ((id(*)(id, SEL, id))objc_msgSend)(
                              js_nsstring, "stringByAppendingString:"_sel,
                              ((id(*)(id, SEL, const char *))objc_msgSend)(
                                  "NSString"_cls, "stringWithUTF8String:"_sel, js_second));
                      ((void (*)(id, SEL, id, id))objc_msgSend)(
                          w->m_webview, "evaluateJavaScript:completionHandler:"_sel,
                          js_nsstring,
                          nullptr);
                    }),
                    "v@:");
    class_addMethod(cls, "add_bookmark:"_sel,
                    (IMP)(+[](id self, SEL) {
                      auto w =
                          (cocoa_wkwebview_engine *)objc_getAssociatedObject(
                              self, "webview");
                      assert(w);
                      id dialog = ((id(*)(id, SEL))objc_msgSend)(
                          ((id(*)(id, SEL))objc_msgSend)("NSAlert"_cls, "alloc"_sel),
                          "init"_sel);
                      id url = ((id (*)(id, SEL))objc_msgSend)(
                          ((id (*)(id, SEL))objc_msgSend)(w->m_webview, "URL"_sel),
                          "absoluteString"_sel);
                      BOOL has_prefix_http = ((BOOL (*)(id, SEL, id))objc_msgSend)(url,
                          "hasPrefix:"_sel,
                          "http"_str);
                      if (!has_prefix_http) {
                          id scheme = ((id (*)(id, SEL))objc_msgSend)(
                              ((id (*)(id, SEL))objc_msgSend)(w->m_webview, "URL"_sel),
                              "scheme"_sel);
                          id info_text = ((id(*)(id, SEL, id))objc_msgSend)(
                                  "This page scheme is '"_str, "stringByAppendingString:"_sel, scheme);
                          info_text = ((id(*)(id, SEL, id))objc_msgSend)(
                                  info_text, "stringByAppendingString:"_sel, "'."_str);
                          ((void (*)(id, SEL, id))objc_msgSend)(
                              dialog, "setMessageText:"_sel, "Current url scheme is not 'http' or 'https'."_str);
                          ((void (*)(id, SEL, id))objc_msgSend)(
                              dialog, "setInformativeText:"_sel, info_text);
                          ((void (*)(id, SEL, id))objc_msgSend)(
                              dialog, "addButtonWithTitle:"_sel, "Close"_str);
                          ((id (*)(id, SEL))objc_msgSend)(
                              dialog, "runModal"_sel);
                          return;
                      }
                      ((void (*)(id, SEL, id))objc_msgSend)(
                          dialog, "setMessageText:"_sel, "Are you sure to bookmark this page?"_str);
                      ((void (*)(id, SEL, id))objc_msgSend)(
                          dialog, "setInformativeText:"_sel, url);
                      ((void (*)(id, SEL, id))objc_msgSend)(
                          dialog, "addButtonWithTitle:"_sel, "OK"_str);
                      ((void (*)(id, SEL, id))objc_msgSend)(
                          dialog, "addButtonWithTitle:"_sel, "Cancel"_str);
                      id result = ((id (*)(id, SEL))objc_msgSend)(
                          dialog, "runModal"_sel);
                      if (1000 == (long)result) {
                          // if OK
                          const char *js_first = "onAddBookmark('";
                          const char *url_char = ((const char * (*)(id, SEL))objc_msgSend)(url, "UTF8String"_sel);
                          const char *js_second = "');";
                          id js_nsstring = ((id(*)(id, SEL, const char *))objc_msgSend)(
                                  "NSString"_cls, "stringWithUTF8String:"_sel, js_first);
                          js_nsstring = ((id(*)(id, SEL, id))objc_msgSend)(
                                  js_nsstring, "stringByAppendingString:"_sel,
                                  ((id(*)(id, SEL, const char *))objc_msgSend)(
                                      "NSString"_cls, "stringWithUTF8String:"_sel, url_char));
                          js_nsstring = ((id(*)(id, SEL, id))objc_msgSend)(
                                  js_nsstring, "stringByAppendingString:"_sel,
                                  ((id(*)(id, SEL, const char *))objc_msgSend)(
                                      "NSString"_cls, "stringWithUTF8String:"_sel, js_second));
                          ((void (*)(id, SEL, id, id))objc_msgSend)(
                              w->m_webview, "evaluateJavaScript:completionHandler:"_sel,
                              js_nsstring,
                              nullptr);
                      }
                    }),
                    "v@:");
    class_addMethod(cls, "show_bookmark:"_sel,
                    (IMP)(+[](id self, SEL) {
                      auto w =
                          (cocoa_wkwebview_engine *)objc_getAssociatedObject(
                              self, "webview");
                      assert(w);
                      const char *js = {
                          "onShowBookmark();"
                          };
                      ((void (*)(id, SEL, id, id))objc_msgSend)(
                          w->m_webview, "evaluateJavaScript:completionHandler:"_sel,
                          ((id(*)(id, SEL, const char *))objc_msgSend)(
                              "NSString"_cls, "stringWithUTF8String:"_sel, js),
                          nullptr);
                    }),
                    "v@:");
    objc_registerClassPair(cls);

    auto delegate = ((id(*)(id, SEL))objc_msgSend)((id)cls, "new"_sel);
    objc_setAssociatedObject(delegate, "webview", (id)this,
                             OBJC_ASSOCIATION_ASSIGN);
    ((void (*)(id, SEL, id))objc_msgSend)(app, sel_registerName("setDelegate:"),
                                          delegate);

    //id menubar = [[NSMenu alloc] init];
    id menubar = ((id(*)(id, SEL))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenu"_cls, "alloc"_sel),
                     "init"_sel);

    //id appMenuItem = [[NSMenuItem alloc] init];
    id appMenuItem = ((id(*)(id, SEL))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenuItem"_cls, "alloc"_sel),
                     "init"_sel);

    //id editMenuItem = [[NSMenuItem alloc] init];
    id editMenuItem = ((id(*)(id, SEL))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenuItem"_cls, "alloc"_sel),
                     "init"_sel);

    //id bookmarkMenuItem = [[NSMenuItem alloc] init];
    id bookmarkMenuItem = ((id(*)(id, SEL))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenuItem"_cls, "alloc"_sel),
                     "init"_sel);

    //[menubar addItem:appMenuItem];
    ((id(*)(id, SEL, id))objc_msgSend)(
                     menubar,
                     "addItem:"_sel,
                     appMenuItem);

    //[menubar addItem:editMenuItem];
    ((id(*)(id, SEL, id))objc_msgSend)(
                     menubar,
                     "addItem:"_sel,
                     editMenuItem);

    //[menubar addItem:bookmarkMenuItem];
    ((id(*)(id, SEL, id))objc_msgSend)(
                     menubar,
                     "addItem:"_sel,
                     bookmarkMenuItem);

    //[NSApp setMainMenu:menubar];
    ((id(*)(id, SEL, id))objc_msgSend)(
                     app,
                     "setMainMenu:"_sel,
                     menubar);

    //id appMenu = [[NSMenu alloc] init];
    id appMenu = ((id(*)(id, SEL))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenu"_cls, "alloc"_sel),
                     "init"_sel);

    //id appName = [[NSProcessInfo processInfo] processName];
    id appName = ((id(*)(id, SEL))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSProcessInfo"_cls, "processInfo"_sel),
                     "processName"_sel);

    //id quitTitle = [@"Quit " stringByAppendingString:appName];
    id quitTitle = ((id(*)(id, SEL, id))objc_msgSend)(
                     "Quit "_str,
                     "stringByAppendingString:"_sel,
                     appName);

    //id quitMenuItem = [[NSMenuItem alloc] initWithTitle:quitTitle action:@selector(terminate:) keyEquivalent:@"q"];
    id quitMenuItem = ((id(*)(id, SEL, id, SEL, id))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenuItem"_cls, "alloc"_sel),
                     "initWithTitle:action:keyEquivalent:"_sel,
                     quitTitle,
                     "terminate:"_sel,
                     "q"_str);

    //id removeCacheMenuItem = [[NSMenuItem alloc] initWithTitle:@"Remove Cache" action:@selector(removeCache:) keyEquivalent:@"r"];
    id removeCacheMenuItem = ((id(*)(id, SEL, id, SEL, id))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenuItem"_cls, "alloc"_sel),
                     "initWithTitle:action:keyEquivalent:"_sel,
                     "Remove Cache"_str,
                     "removeCache:"_sel,
                     "r"_str);

    //id snapshotMenuItem = [[NSMenuItem alloc] initWithTitle:@"Snapshot" action:@selector(snapshot:) keyEquivalent:@"s"];
    id snapshotMenuItem = ((id(*)(id, SEL, id, SEL, id))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenuItem"_cls, "alloc"_sel),
                     "initWithTitle:action:keyEquivalent:"_sel,
                     "Snapshot"_str,
                     "snapshot:"_sel,
                     "s"_str);

    //id editMenu = [[NSMenu alloc] init];
    id editMenu = ((id(*)(id, SEL))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenu"_cls, "alloc"_sel),
                     "init"_sel);

    //[editMenu setTitle:@"Edit"];
    ((void(*)(id, SEL, id))objc_msgSend)(editMenu, "setTitle:"_sel, "Edit"_str);

    //id copyMenuItem = [[NSMenuItem alloc] initWithTitle:@"Copy" action:@selector(text_copy:) keyEquivalent:@"c"];
    id copyMenuItem = ((id(*)(id, SEL, id, SEL, id))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenuItem"_cls, "alloc"_sel),
                     "initWithTitle:action:keyEquivalent:"_sel,
                     "Copy"_str,
                     "copy_text:"_sel,
                     "c"_str);

    //id pasteMenuItem = [[NSMenuItem alloc] initWithTitle:@"Paste" action:@selector(text_paste:) keyEquivalent:@"p"];
    id pasteMenuItem = ((id(*)(id, SEL, id, SEL, id))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenuItem"_cls, "alloc"_sel),
                     "initWithTitle:action:keyEquivalent:"_sel,
                     "Paste"_str,
                     "paste_text:"_sel,
                     "v"_str);

    //id bookmarkMenu = [[NSMenu alloc] init];
    id bookmarkMenu = ((id(*)(id, SEL))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenu"_cls, "alloc"_sel),
                     "init"_sel);

    //[bookmarkMenu setTitle:@"Bookmark"];
    ((void(*)(id, SEL, id))objc_msgSend)(bookmarkMenu, "setTitle:"_sel, "Bookmark"_str);

    //id addBookmarkMenuItem = [[NSMenuItem alloc] initWithTitle:@"Add Bookmark" action:@selector(add_bookmark:) keyEquivalent:@"b"];
    id addBookmarkMenuItem = ((id(*)(id, SEL, id, SEL, id))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenuItem"_cls, "alloc"_sel),
                     "initWithTitle:action:keyEquivalent:"_sel,
                     "Add Bookmark"_str,
                     "add_bookmark:"_sel,
                     "b"_str);

    //id showBookmarkMenuItem = [[NSMenuItem alloc] initWithTitle:@"Show Bookmark" action:@selector(show_bookmark:) keyEquivalent:@"l"];
    id showBookmarkMenuItem = ((id(*)(id, SEL, id, SEL, id))objc_msgSend)(
                     ((id(*)(id, SEL))objc_msgSend)("NSMenuItem"_cls, "alloc"_sel),
                     "initWithTitle:action:keyEquivalent:"_sel,
                     "Show Bookmark"_str,
                     "show_bookmark:"_sel,
                     "l"_str);

    //[appMenu addItem:quitMenuItem];
    ((void (*)(id, SEL, id))objc_msgSend)(
                     appMenu,
                     "addItem:"_sel,
                     quitMenuItem);

    //[appMenu addItem:removeCacheMenuItem];
    ((void (*)(id, SEL, id))objc_msgSend)(
                     appMenu,
                     "addItem:"_sel,
                     removeCacheMenuItem);

    //[appMenu addItem:snapshotMenuItem];
    ((void (*)(id, SEL, id))objc_msgSend)(
                     appMenu,
                     "addItem:"_sel,
                     snapshotMenuItem);

    //[appMenuItem setSubmenu:appMenu];
    ((void (*)(id, SEL, id))objc_msgSend)(
                     appMenuItem,
                     "setSubmenu:"_sel,
                     appMenu);

    //[editMenu addItem:copyMenuItem];
    ((id(*)(id, SEL, id))objc_msgSend)(
                     editMenu,
                     "addItem:"_sel,
                     copyMenuItem);

    //[editMenu addItem:pasteMenuItem];
    ((id(*)(id, SEL, id))objc_msgSend)(
                     editMenu,
                     "addItem:"_sel,
                     pasteMenuItem);

    //[editMenuItem setSubmenu:editMenu];
    ((id(*)(id, SEL, id))objc_msgSend)(
                     editMenuItem,
                     "setSubmenu:"_sel,
                     editMenu);

    //[bookmarkMenu addItem:addBookmarkMenuItem];
    ((id(*)(id, SEL, id))objc_msgSend)(
                     bookmarkMenu,
                     "addItem:"_sel,
                     addBookmarkMenuItem);

    //[bookmarkMenu addItem:showBookmarkMenuItem];
    ((id(*)(id, SEL, id))objc_msgSend)(
                     bookmarkMenu,
                     "addItem:"_sel,
                     showBookmarkMenuItem);

    //[bookmarkMenuItem setSubmenu:bookmarkMenu];
    ((id(*)(id, SEL, id))objc_msgSend)(
                     bookmarkMenuItem,
                     "setSubmenu:"_sel,
                     bookmarkMenu);

    // Main window
    if (window == nullptr) {
      m_window = ((id(*)(id, SEL))objc_msgSend)("NSWindow"_cls, "alloc"_sel);
      m_window =
          ((id(*)(id, SEL, CGRect, int, unsigned long, int))objc_msgSend)(
              m_window, "initWithContentRect:styleMask:backing:defer:"_sel,
              CGRectMake(0, 0, 0, 0), 0, NSBackingStoreBuffered, 0);
    } else {
      m_window = (id)window;
    }

    // Webview
    auto config =
        ((id(*)(id, SEL))objc_msgSend)("WKWebViewConfiguration"_cls, "new"_sel);
    m_manager =
        ((id(*)(id, SEL))objc_msgSend)(config, "userContentController"_sel);
    m_webview = ((id(*)(id, SEL))objc_msgSend)("WKWebView"_cls, "alloc"_sel);
    m_host = ""_str;

    if (debug) {
      // Equivalent Obj-C:
      // [[config preferences] setValue:@YES forKey:@"developerExtrasEnabled"];
      ((id(*)(id, SEL, id, id))objc_msgSend)(
          ((id(*)(id, SEL))objc_msgSend)(config, "preferences"_sel),
          "setValue:forKey:"_sel,
          ((id(*)(id, SEL, BOOL))objc_msgSend)("NSNumber"_cls,
                                               "numberWithBool:"_sel, 1),
          "developerExtrasEnabled"_str);
    }

    // Equivalent Obj-C:
    // [[config preferences] setValue:@YES forKey:@"fullScreenEnabled"];
    ((id(*)(id, SEL, id, id))objc_msgSend)(
        ((id(*)(id, SEL))objc_msgSend)(config, "preferences"_sel),
        "setValue:forKey:"_sel,
        ((id(*)(id, SEL, BOOL))objc_msgSend)("NSNumber"_cls,
                                             "numberWithBool:"_sel, 1),
        "fullScreenEnabled"_str);

    // Equivalent Obj-C:
    // [[config preferences] setValue:@YES forKey:@"javaScriptCanAccessClipboard"];
    ((id(*)(id, SEL, id, id))objc_msgSend)(
        ((id(*)(id, SEL))objc_msgSend)(config, "preferences"_sel),
        "setValue:forKey:"_sel,
        ((id(*)(id, SEL, BOOL))objc_msgSend)("NSNumber"_cls,
                                             "numberWithBool:"_sel, 1),
        "javaScriptCanAccessClipboard"_str);

    // Equivalent Obj-C:
    // [[config preferences] setValue:@YES forKey:@"DOMPasteAllowed"];
    ((id(*)(id, SEL, id, id))objc_msgSend)(
        ((id(*)(id, SEL))objc_msgSend)(config, "preferences"_sel),
        "setValue:forKey:"_sel,
        ((id(*)(id, SEL, BOOL))objc_msgSend)("NSNumber"_cls,
                                             "numberWithBool:"_sel, 1),
        "DOMPasteAllowed"_str);

    ((void (*)(id, SEL, CGRect, id))objc_msgSend)(
        m_webview, "initWithFrame:configuration:"_sel, CGRectMake(0, 0, 0, 0),
        config);
    ((void (*)(id, SEL, id, id))objc_msgSend)(
        m_manager, "addScriptMessageHandler:name:"_sel, delegate,
        "external"_str);

    // [_webView setNavigationDelegate:self];
    ((void (*)(id, SEL, id))objc_msgSend)(m_webview,
        "setNavigationDelegate:"_sel, delegate);
    // [_webView setUIDelegate:self];
    ((void (*)(id, SEL, id))objc_msgSend)(m_webview,
        "setUIDelegate:"_sel, delegate);

    init(R"script(
                      window.external = {
                        invoke: function(s) {
                          window.webkit.messageHandlers.external.postMessage(s);
                        },
                      };
                     )script");
    ((void (*)(id, SEL, id))objc_msgSend)(m_window, "setContentView:"_sel,
                                          m_webview);
    ((void (*)(id, SEL, id))objc_msgSend)(m_window, "makeKeyAndOrderFront:"_sel,
                                          nullptr);
  }
  ~cocoa_wkwebview_engine() { close(); }
  void *window() { return (void *)m_window; }
  void terminate() {
    close();
    ((void (*)(id, SEL, id))objc_msgSend)("NSApp"_cls, "terminate:"_sel,
                                          nullptr);
  }
  void run() {
    id app = ((id(*)(id, SEL))objc_msgSend)("NSApplication"_cls,
                                            "sharedApplication"_sel);
    dispatch([&]() {
      ((void (*)(id, SEL, BOOL))objc_msgSend)(
          app, "activateIgnoringOtherApps:"_sel, 1);
    });
    ((void (*)(id, SEL))objc_msgSend)(app, "run"_sel);
  }
  void dispatch(std::function<void()> f) {
    dispatch_async_f(dispatch_get_main_queue(), new dispatch_fn_t(f),
                     (dispatch_function_t)([](void *arg) {
                       auto f = static_cast<dispatch_fn_t *>(arg);
                       (*f)();
                       delete f;
                     }));
  }
  void set_title(const std::string title) {
    ((void (*)(id, SEL, id))objc_msgSend)(
        m_window, "setTitle:"_sel,
        ((id(*)(id, SEL, const char *))objc_msgSend)(
            "NSString"_cls, "stringWithUTF8String:"_sel, title.c_str()));
  }
  void set_size(int width, int height, int hints) {
    auto style = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                 NSWindowStyleMaskMiniaturizable;
    if (hints != WEBVIEW_HINT_FIXED) {
      style = style | NSWindowStyleMaskResizable;
    }
    ((void (*)(id, SEL, unsigned long))objc_msgSend)(
        m_window, "setStyleMask:"_sel, style);

    if (hints == WEBVIEW_HINT_MIN) {
      ((void (*)(id, SEL, CGSize))objc_msgSend)(
          m_window, "setContentMinSize:"_sel, CGSizeMake(width, height));
    } else if (hints == WEBVIEW_HINT_MAX) {
      ((void (*)(id, SEL, CGSize))objc_msgSend)(
          m_window, "setContentMaxSize:"_sel, CGSizeMake(width, height));
    } else {
      ((void (*)(id, SEL, CGRect, BOOL, BOOL))objc_msgSend)(
          m_window, "setFrame:display:animate:"_sel,
          CGRectMake(0, 0, width, height), 1, 0);
    }
    ((void (*)(id, SEL))objc_msgSend)(m_window, "center"_sel);
  }
  void navigate(const std::string url) {
    auto nsurl = ((id(*)(id, SEL, id))objc_msgSend)(
        "NSURL"_cls, "URLWithString:"_sel,
        ((id(*)(id, SEL, const char *))objc_msgSend)(
            "NSString"_cls, "stringWithUTF8String:"_sel, url.c_str()));

    ((void (*)(id, SEL, id))objc_msgSend)(
        m_webview, "loadRequest:"_sel,
        ((id(*)(id, SEL, id))objc_msgSend)("NSURLRequest"_cls,
                                           "requestWithURL:"_sel, nsurl));
  }
  void init(const std::string js) {
    // Equivalent Obj-C:
    // [m_manager addUserScript:[[WKUserScript alloc] initWithSource:[NSString stringWithUTF8String:js.c_str()] injectionTime:WKUserScriptInjectionTimeAtDocumentStart forMainFrameOnly:YES]]
    ((void (*)(id, SEL, id))objc_msgSend)(
        m_manager, "addUserScript:"_sel,
        ((id(*)(id, SEL, id, long, BOOL))objc_msgSend)(
            ((id(*)(id, SEL))objc_msgSend)("WKUserScript"_cls, "alloc"_sel),
            "initWithSource:injectionTime:forMainFrameOnly:"_sel,
            ((id(*)(id, SEL, const char *))objc_msgSend)(
                "NSString"_cls, "stringWithUTF8String:"_sel, js.c_str()),
            WKUserScriptInjectionTimeAtDocumentStart, 1));
  }
  void eval(const std::string js) {
    ((void (*)(id, SEL, id, id))objc_msgSend)(
        m_webview, "evaluateJavaScript:completionHandler:"_sel,
        ((id(*)(id, SEL, const char *))objc_msgSend)(
            "NSString"_cls, "stringWithUTF8String:"_sel, js.c_str()),
        nullptr);
  }
  void screenshot(const std::string path) {
    CGRect webview_frame = ((CGRect (*)(id, SEL))objc_msgSend_stret)(m_webview, "frame"_sel);
    auto snapshot_configuration = ((id(*)(id, SEL))objc_msgSend)("WKSnapshotConfiguration"_cls, "new"_sel);
    ((void (*)(id, SEL, CGRect))objc_msgSend)(snapshot_configuration, "setRect:"_sel, webview_frame);
    ((void (*)(id, SEL, BOOL))objc_msgSend)(snapshot_configuration, "setAfterScreenUpdates:"_sel, 0);

    id block = (id)(^(id img, CGError err) {
      if (!err) {
        // convert image type PNG
        id data = ((id(*)(id, SEL))objc_msgSend)(img, "TIFFRepresentation"_sel);
        id bitmapImageRep = ((id(*)(id, SEL, id))objc_msgSend)("NSBitmapImageRep"_cls, "imageRepWithData:"_sel, data);
        id properties = ((id(*)(id, SEL, id, id))objc_msgSend)(
            "NSDictionary"_cls, "dictionaryWithObject:forKey:"_sel,
            ((id(*)(id, SEL, BOOL))objc_msgSend)("NSNumber"_cls, "numberWithBool:"_sel, 1),
            "NSImageInterlaced"_str);
        id data_ = ((id(*)(id, SEL, unsigned long, id))objc_msgSend)(bitmapImageRep,
            "representationUsingType:properties:"_sel,
            NSPNGFileType,
            properties);

        // save image
        id result_file = ((id(*)(id, SEL, const char *))objc_msgSend)(
            "NSString"_cls, "stringWithUTF8String:"_sel, path.c_str());
        ((void (*)(id, SEL, id, BOOL))objc_msgSend)(
            data_, "writeToFile:atomically:"_sel, result_file, 1);
      }
    });
    // take snapshot
    ((void (*)(id, SEL, id, id))objc_msgSend)(
        m_webview,"takeSnapshotWithConfiguration:completionHandler:"_sel,
        snapshot_configuration,
        block
    );
  }
  void custom_context_menu(const std::string message) {
    id menu = ((id(*)(id, SEL, id))objc_msgSend)(
        ((id(*)(id, SEL))objc_msgSend)("NSMenu"_cls, "alloc"_sel),
        "initWithTitle:"_sel,
        "Context Menu"_str);
    ((void (*)(id, SEL, id, SEL, id, int))objc_msgSend)(
        menu, "insertItemWithTitle:action:keyEquivalent:atIndex:"_sel,
        "Screenshot"_str,
        "snapshot:"_sel,
        ""_str, 0);
    ((void (*)(id, SEL, id, SEL, id, int))objc_msgSend)(
        menu, "insertItemWithTitle:action:keyEquivalent:atIndex:"_sel,
        "Reload"_str,
        "reload:"_sel,
        ""_str, 1);
    if (message.length() == 1 && message[0] =='A') {
        ((void (*)(id, SEL, id, SEL, id, int))objc_msgSend)(
            menu, "insertItemWithTitle:action:keyEquivalent:atIndex:"_sel,
            "Copy Link"_str,
            "copy_link:"_sel,
            ""_str, 2);
    }
    ((void (*)(id, SEL, id, id, id))objc_msgSend)(
        menu, "popUpMenuPositioningItem:atLocation:inView:"_sel,
        ((id (*)(id, SEL, int))objc_msgSend)(
            ((id(*)(id, SEL))objc_msgSend)(menu, "itemArray"_sel),
            "objectAtIndex:"_sel,
            0),
        ((id(*)(id, SEL))objc_msgSend)("NSEvent"_cls, "mouseLocation"_sel),
        m_webview);
  }
  void set_not_allowed_host(const std::string host) {
     m_host = ((id(*)(id, SEL, const char *))objc_msgSend)(
            "NSString"_cls, "stringWithUTF8String:"_sel, host.c_str());
  }

private:
  virtual void on_message(const std::string msg) = 0;
  void close() { ((void (*)(id, SEL))objc_msgSend)(m_window, "close"_sel); }
  id m_window;
  id m_webview;
  id m_manager;
  id m_host;
};

using browser_engine = cocoa_wkwebview_engine;

} // namespace webview

#elif defined(WEBVIEW_EDGE)

//
// ====================================================================
//
// This implementation uses Win32 API to create a native window. It can
// use either EdgeHTML or Edge/Chromium backend as a browser engine.
//
// ====================================================================
//

#define WIN32_LEAN_AND_MEAN
#include <Shlwapi.h>
#include <codecvt>
#include <stdlib.h>
#include <windows.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Shlwapi.lib")

// EdgeHTML headers and libs
#include <objbase.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Web.UI.Interop.h>
#pragma comment(lib, "windowsapp")

// Edge/Chromium headers and libs
#include "webview2.h"
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace webview {

using msg_cb_t = std::function<void(const std::string)>;

// Common interface for EdgeHTML and Edge/Chromium
class browser {
public:
  virtual ~browser() = default;
  virtual bool embed(HWND, bool, msg_cb_t) = 0;
  virtual void navigate(const std::string url) = 0;
  virtual void eval(const std::string js) = 0;
  virtual void init(const std::string js) = 0;
  virtual void screenshot(const std::string path) = 0;
  virtual void custom_context_menu(const std::string message) = 0;
  virtual void set_not_allowed_host(const std::string host) = 0;
  virtual void resize(HWND) = 0;
};

//
// EdgeHTML browser engine
//
using namespace winrt;
using namespace Windows::Foundation;
using namespace Windows::Web::UI;
using namespace Windows::Web::UI::Interop;

class edge_html : public browser {
public:
  bool embed(HWND wnd, bool debug, msg_cb_t cb) override {
    init_apartment(winrt::apartment_type::single_threaded);
    auto process = WebViewControlProcess();
    auto op = process.CreateWebViewControlAsync(reinterpret_cast<int64_t>(wnd),
                                                Rect());
    if (op.Status() != AsyncStatus::Completed) {
      handle h(CreateEvent(nullptr, false, false, nullptr));
      op.Completed([h = h.get()](auto, auto) { SetEvent(h); });
      HANDLE hs[] = {h.get()};
      DWORD i;
      CoWaitForMultipleHandles(COWAIT_DISPATCH_WINDOW_MESSAGES |
                                   COWAIT_DISPATCH_CALLS |
                                   COWAIT_INPUTAVAILABLE,
                               INFINITE, 1, hs, &i);
    }
    m_webview = op.GetResults();
    m_webview.Settings().IsScriptNotifyAllowed(true);
    m_webview.IsVisible(true);
    m_webview.ScriptNotify([=](auto const &sender, auto const &args) {
      std::string s = winrt::to_string(args.Value());
      cb(s.c_str());
    });
    m_webview.NavigationStarting([=](auto const &sender, auto const &args) {
      m_webview.AddInitializeScript(winrt::to_hstring(init_js));
    });
    init("window.external.invoke = s => window.external.notify(s)");
    return true;
  }

  void navigate(const std::string url) override {
    std::string html = html_from_uri(url);
    if (html != "") {
      m_webview.NavigateToString(winrt::to_hstring(html));
    } else {
      Uri uri(winrt::to_hstring(url));
      m_webview.Navigate(uri);
    }
  }

  void init(const std::string js) override {
    init_js = init_js + "(function(){" + js + "})();";
  }

  void eval(const std::string js) override {
    m_webview.InvokeScriptAsync(
        L"eval", single_threaded_vector<hstring>({winrt::to_hstring(js)}));
  }

  void screenshot(const std::string path) override {
    // TODO
  }

  void custom_context_menu(const std::string message) override {
    // TODO
  }

  void set_not_allowed_host(const std::string host) override {
    // TODO
  }

  void resize(HWND wnd) override {
    if (m_webview == nullptr) {
      return;
    }
    RECT r;
    GetClientRect(wnd, &r);
    Rect bounds(r.left, r.top, r.right - r.left, r.bottom - r.top);
    m_webview.Bounds(bounds);
  }

private:
  WebViewControl m_webview = nullptr;
  std::string init_js = "";
};

//
// Edge/Chromium browser engine
//
class edge_chromium : public browser {
public:
  bool embed(HWND wnd, bool debug, msg_cb_t cb) override {
    CoInitializeEx(nullptr, 0);
    std::atomic_flag flag = ATOMIC_FLAG_INIT;
    flag.test_and_set();

    char currentExePath[MAX_PATH];
    GetModuleFileNameA(NULL, currentExePath, MAX_PATH);
    char *currentExeName = PathFindFileNameA(currentExePath);

    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> wideCharConverter;
    std::wstring userDataFolder =
        wideCharConverter.from_bytes(std::getenv("APPDATA"));
    std::wstring currentExeNameW = wideCharConverter.from_bytes(currentExeName);

    HRESULT res = CreateCoreWebView2EnvironmentWithOptions(
        nullptr, (userDataFolder + L"/" + currentExeNameW).c_str(), nullptr,
        new webview2_com_handler(wnd, cb,
                                 [&](ICoreWebView2Controller *controller) {
                                   m_controller = controller;
                                   m_controller->get_CoreWebView2(&m_webview);
                                   m_webview->AddRef();
                                   flag.clear();
                                 }));
    if (res != S_OK) {
      CoUninitialize();
      return false;
    }
    MSG msg = {};
    while (flag.test_and_set() && GetMessage(&msg, NULL, 0, 0)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
    init("window.external={invoke:s=>window.chrome.webview.postMessage(s)}");
    return true;
  }

  void resize(HWND wnd) override {
    if (m_controller == nullptr) {
      return;
    }
    RECT bounds;
    GetClientRect(wnd, &bounds);
    m_controller->put_Bounds(bounds);
  }

  void navigate(const std::string url) override {
    auto wurl = to_lpwstr(url);
    m_webview->Navigate(wurl);
    delete[] wurl;
  }

  void init(const std::string js) override {
    LPCWSTR wjs = to_lpwstr(js);
    m_webview->AddScriptToExecuteOnDocumentCreated(wjs, nullptr);
    delete[] wjs;
  }

  void eval(const std::string js) override {
    LPCWSTR wjs = to_lpwstr(js);
    m_webview->ExecuteScript(wjs, nullptr);
    delete[] wjs;
  }

  void screenshot(const std::string path) override {
    // TODO
  }

  void custom_context_menu(const std::string message) override {
    // TODO
  }

  void set_not_allowed_host(const std::string host) override {
    // TODO
  }

private:
  LPWSTR to_lpwstr(const std::string s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
    wchar_t *ws = new wchar_t[n];
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws, n);
    return ws;
  }

  ICoreWebView2 *m_webview = nullptr;
  ICoreWebView2Controller *m_controller = nullptr;

  class webview2_com_handler
      : public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler,
        public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler,
        public ICoreWebView2WebMessageReceivedEventHandler,
        public ICoreWebView2PermissionRequestedEventHandler {
    using webview2_com_handler_cb_t =
        std::function<void(ICoreWebView2Controller *)>;

  public:
    webview2_com_handler(HWND hwnd, msg_cb_t msgCb,
                         webview2_com_handler_cb_t cb)
        : m_window(hwnd), m_msgCb(msgCb), m_cb(cb) {}
    ULONG STDMETHODCALLTYPE AddRef() { return 1; }
    ULONG STDMETHODCALLTYPE Release() { return 1; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, LPVOID *ppv) {
      return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT res,
                                     ICoreWebView2Environment *env) {
      env->CreateCoreWebView2Controller(m_window, this);
      return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Invoke(HRESULT res,
                                     ICoreWebView2Controller *controller) {
      controller->AddRef();

      ICoreWebView2 *webview;
      ::EventRegistrationToken token;
      controller->get_CoreWebView2(&webview);
      webview->add_WebMessageReceived(this, &token);
      webview->add_PermissionRequested(this, &token);

      m_cb(controller);
      return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Invoke(
        ICoreWebView2 *sender, ICoreWebView2WebMessageReceivedEventArgs *args) {
      LPWSTR message;
      args->TryGetWebMessageAsString(&message);

      std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> wideCharConverter;
      m_msgCb(wideCharConverter.to_bytes(message));
      sender->PostWebMessageAsString(message);

      CoTaskMemFree(message);
      return S_OK;
    }
    HRESULT STDMETHODCALLTYPE
    Invoke(ICoreWebView2 *sender,
           ICoreWebView2PermissionRequestedEventArgs *args) {
      COREWEBVIEW2_PERMISSION_KIND kind;
      args->get_PermissionKind(&kind);
      if (kind == COREWEBVIEW2_PERMISSION_KIND_CLIPBOARD_READ) {
        args->put_State(COREWEBVIEW2_PERMISSION_STATE_ALLOW);
      }
      return S_OK;
    }

  private:
    HWND m_window;
    msg_cb_t m_msgCb;
    webview2_com_handler_cb_t m_cb;
  };
};

class win32_edge_engine {
public:
  win32_edge_engine(bool debug, void *window) {
    if (window == nullptr) {
      HINSTANCE hInstance = GetModuleHandle(nullptr);
      HICON icon = (HICON)LoadImage(
          hInstance, IDI_APPLICATION, IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
          GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);

      WNDCLASSEX wc;
      ZeroMemory(&wc, sizeof(WNDCLASSEX));
      wc.cbSize = sizeof(WNDCLASSEX);
      wc.hInstance = hInstance;
      wc.lpszClassName = "webview";
      wc.hIcon = icon;
      wc.hIconSm = icon;
      wc.lpfnWndProc =
          (WNDPROC)(+[](HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) -> int {
            auto w = (win32_edge_engine *)GetWindowLongPtr(hwnd, GWLP_USERDATA);
            switch (msg) {
            case WM_SIZE:
              w->m_browser->resize(hwnd);
              break;
            case WM_CLOSE:
              DestroyWindow(hwnd);
              break;
            case WM_DESTROY:
              w->terminate();
              break;
            case WM_GETMINMAXINFO: {
              auto lpmmi = (LPMINMAXINFO)lp;
              if (w == nullptr) {
                return 0;
              }
              if (w->m_maxsz.x > 0 && w->m_maxsz.y > 0) {
                lpmmi->ptMaxSize = w->m_maxsz;
                lpmmi->ptMaxTrackSize = w->m_maxsz;
              }
              if (w->m_minsz.x > 0 && w->m_minsz.y > 0) {
                lpmmi->ptMinTrackSize = w->m_minsz;
              }
            } break;
            default:
              return DefWindowProc(hwnd, msg, wp, lp);
            }
            return 0;
          });
      RegisterClassEx(&wc);
      m_window = CreateWindow("webview", "", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                              CW_USEDEFAULT, 640, 480, nullptr, nullptr,
                              GetModuleHandle(nullptr), nullptr);
      SetWindowLongPtr(m_window, GWLP_USERDATA, (LONG_PTR)this);
    } else {
      m_window = *(static_cast<HWND *>(window));
    }

    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE);
    ShowWindow(m_window, SW_SHOW);
    UpdateWindow(m_window);
    SetFocus(m_window);

    auto cb =
        std::bind(&win32_edge_engine::on_message, this, std::placeholders::_1);

    if (!m_browser->embed(m_window, debug, cb)) {
      m_browser = std::make_unique<webview::edge_html>();
      m_browser->embed(m_window, debug, cb);
    }

    m_browser->resize(m_window);
  }

  void run() {
    MSG msg;
    BOOL res;
    while ((res = GetMessage(&msg, nullptr, 0, 0)) != -1) {
      if (msg.hwnd) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
        continue;
      }
      if (msg.message == WM_APP) {
        auto f = (dispatch_fn_t *)(msg.lParam);
        (*f)();
        delete f;
      } else if (msg.message == WM_QUIT) {
        return;
      }
    }
  }
  void *window() { return (void *)m_window; }
  void terminate() { PostQuitMessage(0); }
  void dispatch(dispatch_fn_t f) {
    PostThreadMessage(m_main_thread, WM_APP, 0, (LPARAM) new dispatch_fn_t(f));
  }

  void set_title(const std::string title) {
    SetWindowText(m_window, title.c_str());
  }

  void set_size(int width, int height, int hints) {
    auto style = GetWindowLong(m_window, GWL_STYLE);
    if (hints == WEBVIEW_HINT_FIXED) {
      style &= ~(WS_THICKFRAME | WS_MAXIMIZEBOX);
    } else {
      style |= (WS_THICKFRAME | WS_MAXIMIZEBOX);
    }
    SetWindowLong(m_window, GWL_STYLE, style);

    if (hints == WEBVIEW_HINT_MAX) {
      m_maxsz.x = width;
      m_maxsz.y = height;
    } else if (hints == WEBVIEW_HINT_MIN) {
      m_minsz.x = width;
      m_minsz.y = height;
    } else {
      RECT r;
      r.left = r.top = 0;
      r.right = width;
      r.bottom = height;
      AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, 0);
      SetWindowPos(
          m_window, NULL, r.left, r.top, r.right - r.left, r.bottom - r.top,
          SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOMOVE | SWP_FRAMECHANGED);
      m_browser->resize(m_window);
    }
  }

  void navigate(const std::string url) { m_browser->navigate(url); }
  void eval(const std::string js) { m_browser->eval(js); }
  void init(const std::string js) { m_browser->init(js); }
  void screenshot(const std::string path) { m_browser->screenshot(path); }
  void custom_context_menu(const std::string message) { m_browser->custom_context_menu(message); }
  void set_not_allowed_host(const std::string host) { m_browser->set_not_allowed_host(host); }

private:
  virtual void on_message(const std::string msg) = 0;

  HWND m_window;
  POINT m_minsz = POINT{0, 0};
  POINT m_maxsz = POINT{0, 0};
  DWORD m_main_thread = GetCurrentThreadId();
  std::unique_ptr<webview::browser> m_browser =
      std::make_unique<webview::edge_chromium>();
};

using browser_engine = win32_edge_engine;
} // namespace webview

#endif /* WEBVIEW_GTK, WEBVIEW_COCOA, WEBVIEW_EDGE */

namespace webview {

class webview : public browser_engine {
public:
  webview(bool debug = false, void *wnd = nullptr)
      : browser_engine(debug, wnd) {}

  void navigate(const std::string url) {
    if (url == "") {
      browser_engine::navigate("data:text/html," +
                               url_encode("<html><body>Hello</body></html>"));
      return;
    }
    std::string html = html_from_uri(url);
    if (html != "") {
      browser_engine::navigate("data:text/html," + url_encode(html));
    } else {
      browser_engine::navigate(url);
    }
  }

  using binding_t = std::function<void(std::string, std::string, void *)>;
  using binding_ctx_t = std::pair<binding_t *, void *>;

  using sync_binding_t = std::function<std::string(std::string)>;
  using sync_binding_ctx_t = std::pair<webview *, sync_binding_t>;

  void bind(const std::string name, sync_binding_t fn) {
    bind(
        name,
        [](std::string seq, std::string req, void *arg) {
          auto pair = static_cast<sync_binding_ctx_t *>(arg);
          pair->first->resolve(seq, 0, pair->second(req));
        },
        new sync_binding_ctx_t(this, fn));
  }

  void bind(const std::string name, binding_t f, void *arg) {
    auto js = "(function() { var name = '" + name + "';" + R"(
      var RPC = window._rpc = (window._rpc || {nextSeq: 1});
      window[name] = function() {
        var seq = RPC.nextSeq++;
        var promise = new Promise(function(resolve, reject) {
          RPC[seq] = {
            resolve: resolve,
            reject: reject,
          };
        });
        window.external.invoke(JSON.stringify({
          id: seq,
          method: name,
          params: Array.prototype.slice.call(arguments),
        }));
        return promise;
      }
    })())";
    init(js);
    bindings[name] = new binding_ctx_t(new binding_t(f), arg);
  }

  void resolve(const std::string seq, int status, const std::string result) {
    dispatch([=]() {
      if (status == 0) {
        eval("window._rpc[" + seq + "].resolve(" + result + "); window._rpc[" +
             seq + "] = undefined");
      } else {
        eval("window._rpc[" + seq + "].reject(" + result + "); window._rpc[" +
             seq + "] = undefined");
      }
    });
  }

private:
  void on_message(const std::string msg) {
    auto seq = json_parse(msg, "id", 0);
    auto name = json_parse(msg, "method", 0);
    auto args = json_parse(msg, "params", 0);
    if (bindings.find(name) == bindings.end()) {
      return;
    }
    auto fn = bindings[name];
    (*fn->first)(seq, args, fn->second);
  }
  std::map<std::string, binding_ctx_t *> bindings;
};
} // namespace webview

WEBVIEW_API webview_t webview_create(int debug, void *wnd) {
  return new webview::webview(debug, wnd);
}

WEBVIEW_API void webview_destroy(webview_t w) {
  delete static_cast<webview::webview *>(w);
}

WEBVIEW_API void webview_run(webview_t w) {
  static_cast<webview::webview *>(w)->run();
}

WEBVIEW_API void webview_terminate(webview_t w) {
  static_cast<webview::webview *>(w)->terminate();
}

WEBVIEW_API void webview_dispatch(webview_t w, void (*fn)(webview_t, void *),
                                  void *arg) {
  static_cast<webview::webview *>(w)->dispatch([=]() { fn(w, arg); });
}

WEBVIEW_API void *webview_get_window(webview_t w) {
  return static_cast<webview::webview *>(w)->window();
}

WEBVIEW_API void webview_set_title(webview_t w, const char *title) {
  static_cast<webview::webview *>(w)->set_title(title);
}

WEBVIEW_API void webview_set_size(webview_t w, int width, int height,
                                  int hints) {
  static_cast<webview::webview *>(w)->set_size(width, height, hints);
}

WEBVIEW_API void webview_navigate(webview_t w, const char *url) {
  static_cast<webview::webview *>(w)->navigate(url);
}

WEBVIEW_API void webview_init(webview_t w, const char *js) {
  static_cast<webview::webview *>(w)->init(js);
}

WEBVIEW_API void webview_eval(webview_t w, const char *js) {
  static_cast<webview::webview *>(w)->eval(js);
}

WEBVIEW_API void webview_bind(webview_t w, const char *name,
                              void (*fn)(const char *seq, const char *req,
                                         void *arg),
                              void *arg) {
  static_cast<webview::webview *>(w)->bind(
      name,
      [=](std::string seq, std::string req, void *arg) {
        fn(seq.c_str(), req.c_str(), arg);
      },
      arg);
}

WEBVIEW_API void webview_return(webview_t w, const char *seq, int status,
                                const char *result) {
  static_cast<webview::webview *>(w)->resolve(seq, status, result);
}

WEBVIEW_API void webview_screenshot(webview_t w, const char *path) {
  static_cast<webview::webview *>(w)->screenshot(path);
}

WEBVIEW_API void webview_custom_context_menu(webview_t w, const char *message) {
  static_cast<webview::webview *>(w)->custom_context_menu(message);
}

WEBVIEW_API void webview_set_not_allowed_host(webview_t w, const char *host) {
  static_cast<webview::webview *>(w)->set_not_allowed_host(host);
}

#endif /* WEBVIEW_HEADER */

#endif /* WEBVIEW_H */
