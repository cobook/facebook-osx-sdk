#import "FBLoginWindow.h"
#import <AppKit/AppKit.h>
#import <WebKit/WebKit.h>
#import "CBPluginOAuthAuthenticator.h"
#import "FBUtility.h"

static const NSTimeInterval kTimeoutInterval = 180.0;
static NSString* kUserAgent = @"FacebookConnect";

@interface FBLoginWindow ()

@end

@implementation FBLoginWindow {
  NSString *_loginDialogURL;
  NSDictionary *_params;
  id<FBLoginWindowDelegate> _delegate;
  WebView *_webView;
  BOOL _hasDoneFinalRedirect;
  BOOL _hasHandledCallback;
}


- (instancetype)initWithWindow:(NSWindow *)window
                           URL:(NSString *)loginDialogURL
                   loginParams:(NSDictionary *)params
                      delegate:(id<FBLoginWindowDelegate>)delegate
{
  if (self = [super initWithWindow:window]) {
    if (!window) {
      NSWindow *mainWindow = [[NSApplication sharedApplication] mainWindow];

      self.window = [[NSWindow alloc] initWithContentRect:NSZeroRect styleMask:NSTitledWindowMask|NSClosableWindowMask|NSMiniaturizableWindowMask|NSResizableWindowMask backing:NSBackingStoreBuffered defer:NO];
      [self.window setTitle:@"Authorize Facebook"];
      NSRect f = self.window.frame;
      f.size = NSMakeSize(600, 300);
      [self.window setFrame:f display:YES];
      self.window.hidesOnDeactivate = mainWindow.hidesOnDeactivate;
      if (!self.window.isVisible) {
        [self.window center];
      }
    }

    _loginDialogURL = loginDialogURL;
    _params = params;
    _delegate = delegate;
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(windowWillClose:)
                                                 name:NSWindowWillCloseNotification
                                               object:self.window];
    
  }
  return self;
}


- (void)windowWillClose:(NSNotification *)notification
{
  [_delegate fbWindowNotLogin:YES];
}


- (void)show
{
  NSWindow *mainWindow = [[NSApplication sharedApplication] mainWindow];
  [mainWindow addChildWindow:self.window ordered:NSWindowAbove];
  
  _webView = [WebView new];
  [self.window setContentView:_webView];
  [self.window makeFirstResponder:_webView];

  // load the requested initial sign-in page
  [_webView setResourceLoadDelegate:self];
  [_webView setPolicyDelegate:self];

  NSString *html = [CBPluginOAuthAuthenticator createLoadingHTML];
  if ([html length] > 0) {
    [[_webView mainFrame] loadHTMLString:html baseURL:nil];
  }

  const NSTimeInterval kJanuary2011 = 1293840000;
  BOOL isDateValid = ([[NSDate date] timeIntervalSince1970] > kJanuary2011);
  if (isDateValid) {
    [self authenticate];
  } else {
    // clock date is invalid, so signing in would fail with an unhelpful error
    // from the server. Warn the user in an html string showing a watch icon,
    // question mark, and the system date and time. Hopefully this will clue
    // in brighter users, or at least let them make a useful screenshot to show
    // to developers.
    //
    // Even better is for apps to check the system clock and show some more
    // helpful, localized instructions for users; this is really a fallback.
    NSString *htmlTemplate = @"<html><body><div align=center><font size='7'>"
    "&#x231A; ?<br><i>System Clock Incorrect</i><br>%@"
    "</font></div></body></html>";
    NSString *errHTML = [NSString stringWithFormat:htmlTemplate, [NSDate date]];
    
    [[_webView mainFrame] loadHTMLString:errHTML baseURL:nil];
  }
  
}


- (void)authenticate
{
  NSMutableURLRequest* request =
  [NSMutableURLRequest requestWithURL:[self generateURL:_loginDialogURL params:_params]
                          cachePolicy:NSURLRequestReloadIgnoringCacheData
                      timeoutInterval:kTimeoutInterval];

  [request setValue:kUserAgent forHTTPHeaderField:@"User-Agent"];
  [_webView.mainFrame loadRequest:request];
}


- (NSURL*)generateURL:(NSString*)baseURL params:(NSDictionary*)params {
  if (params) {
    NSMutableArray* pairs = [NSMutableArray array];
    for (NSString* key in params.keyEnumerator) {
      NSString* value = [params objectForKey:key];
      NSString* escaped_value = [FBUtility stringByURLEncodingString:value];
      [pairs addObject:[NSString stringWithFormat:@"%@=%@", key, escaped_value]];
    }
    
    NSString* query = [pairs componentsJoinedByString:@"&"];
    NSString* url = [NSString stringWithFormat:@"%@?%@", baseURL, query];
    return [NSURL URLWithString:url];
  } else {
    return [NSURL URLWithString:baseURL];
  }
}


- (BOOL)requestRedirectedToRequest:(NSURLRequest *)redirectedRequest
{
  // for Google's installed app sign-in protocol, we'll look for the
  // end-of-sign-in indicator in the titleChanged: method below
  NSString *redirectURI = _params[@"redirect_uri"];
  if (redirectURI == nil) return NO;
    
  // compare the redirectURI, which tells us when the web sign-in is done,
  // to the actual redirection
  NSURL *redirectURL = [NSURL URLWithString:redirectURI];
  NSURL *requestURL = [redirectedRequest URL];
  
  // avoid comparing to nil host and path values (such as when redirected to
  // "about:blank")
  NSString *requestHost = [requestURL host];
  NSString *requestPath = [requestURL path];
  BOOL isCallback;
  if (requestHost && requestPath) {
    isCallback = [[redirectURL host] isEqual:[requestURL host]]
    && [[redirectURL path] isEqual:[requestURL path]];
  } else if (requestURL) {
    // handle "about:blank"
    isCallback = [redirectURL isEqual:requestURL];
  } else {
    isCallback = NO;
  }
  
  if (!isCallback) {
    // tell the caller that this request is nothing interesting
    return NO;
  }
  
  // we've reached the callback URL
  
  // try to get the access code
  if (!_hasHandledCallback) {
    NSString *responseStr = [[redirectedRequest URL] absoluteString];

    // extract token, expiraton or error
    NSString *token = [self getStringFromUrl:responseStr needle:@"access_token="];
    NSString *expTime = [self getStringFromUrl:responseStr needle:@"expires_in="];
    NSDate *expirationDate =nil;
    
    if (expTime != nil) {
      int expVal = [expTime intValue];
      if (expVal == 0) {
        expirationDate = [NSDate distantFuture];
      } else {
        expirationDate = [NSDate dateWithTimeIntervalSinceNow:expVal];
      }
    }
    
    if ((token == (NSString *) [NSNull null]) || (token.length == 0)) {
      [_delegate fbWindowNotLogin:NO];
    } else {
      [_delegate fbWindowLogin:token expirationDate:expirationDate];
    }
  }
  // tell the delegate that we did handle this request
  return YES;
}


/**
 * Find a specific parameter from the url
 */
- (NSString *) getStringFromUrl: (NSString*) url needle:(NSString *) needle {
  NSString * str = nil;
  NSRange start = [url rangeOfString:needle];
  if (start.location != NSNotFound) {
    // confirm that the parameter is not a partial name match
    unichar c = '?';
    if (start.location != 0) {
      c = [url characterAtIndex:start.location - 1];
    }
    if (c == '?' || c == '&' || c == '#') {
      NSRange end = [[url substringFromIndex:start.location+start.length] rangeOfString:@"&"];
      NSUInteger offset = start.location+start.length;
      str = end.location == NSNotFound ?
      [url substringFromIndex:offset] :
      [url substringWithRange:NSMakeRange(offset, end.location)];
      str = [str stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    }
  }
  return str;
}

#pragma mark WebView methods

- (NSURLRequest *)webView:(WebView *)sender resource:(id)identifier willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse fromDataSource:(WebDataSource *)dataSource {
  
  NSString *absoluteURL = [request.URL absoluteString];
  NSLog(@"url: %@", absoluteURL);
  if (!_hasDoneFinalRedirect) {
    _hasDoneFinalRedirect = [self requestRedirectedToRequest:request];
    if (_hasDoneFinalRedirect) {
      // signIn has told the window to close
      return nil;
    }
  }
  return request;
}




@end
