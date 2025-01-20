import {HttpEvent, HttpHandlerFn, HttpHeaders, HttpRequest} from "@angular/common/http";
import {Observable} from "rxjs";
import {environment} from "./environment";

export function withCredentialsInterceptor(request: HttpRequest<unknown>, next: HttpHandlerFn): Observable<HttpEvent<unknown>> {
  const csrfToken = document.cookie
      .split(';')
      .find(cookie => cookie.trim().startsWith('XSRF-TOKEN='));
    console.log('csrfToken: ' + csrfToken);
    let csrfTokenValue = csrfToken ? csrfToken.split('=')[1] : '';
    let csrfHeader = request.headers.set('X-XSRF-TOKEN', csrfTokenValue);
  request = request.clone({
    url: request.url,
    withCredentials: true,
    headers: csrfHeader   // This is required to ensure the Session Cookie is passed in every request to the Backend
  });
  return next(request);
}
