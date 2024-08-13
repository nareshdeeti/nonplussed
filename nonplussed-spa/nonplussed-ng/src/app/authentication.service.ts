import { HttpClient, HttpHeaders } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { BehaviorSubject, Observable } from "rxjs";
import { CurrentUser } from "./login/current-user";

@Injectable({ providedIn: "root" })
export class AuthenticationService {
  // private isAuthenticatedSubject = new BehaviorSubject<boolean | null>(null);
  authenticated = false;

  public static csrfToken: string = "";

  constructor(private http: HttpClient) {
    // this.checkIsAuthenticated();
  }

  /* private checkIsAuthenticated() {
    this.http.get<void>("/users/me")
      .subscribe({
        next: () => this.isAuthenticatedSubject.next(true),
        error: () => this.isAuthenticatedSubject.next(false)
      })
  } */

  /* get isAuthenticated(): Observable<boolean | null> {
    return this.isAuthenticatedSubject.asObservable();
  } */

  authenticate(credentials: any, callback: any) {
    const headers = new HttpHeaders(
      credentials
        ? {
            authorization:
              "Basic " +
              btoa(credentials.username + ":" + credentials.password),
          }
        : {},
    );
    console.log("headers: " + headers);
    let csrfHeader = new HttpHeaders();
    let csrf: any = window.localStorage.getItem('csrfToken');
    csrfHeader = csrfHeader.set('X-XSRF-TOKEN', csrf);
    console.log(credentials);
    // headers.set('X-XSRF-TOKEN', csrfToken);

    this.http
      .post<any>("http://localhost:8011/nonplussed/users/me", {observe: "response",
        headers: headers,
      })
      .subscribe((response: any) => {
        console.log("loging response");
        console.log(response);
        console.log("headers");
        console.log(response.headers);
        console.log("headers csrf");
        console.log(JSON.stringify(response.headers.keys()));
        if (response?.body?.username) {
          // if (response) {
          this.authenticated = true;

          this.http.get<any>("http://localhost:8011/nonplussed/csrf")
            .subscribe((response) => {
              AuthenticationService.csrfToken = response.token;
              console.log("csrfToken: " + AuthenticationService.csrfToken);
              // window.localStorage.setItem('csrfToken', AuthenticationService.csrfToken);
            });
        } else {
          this.authenticated = false;
        }
        return callback && callback();
      });
    return this.formLogin(credentials, callback);
  }

  formLogin(credentials: any, callback: any) {
    const headers = new HttpHeaders();
    headers.set("Content-Type", "application/x-www-form-urlencoded");
    console.log("headers: " + headers);
    console.log("credentials" + credentials);

    this.http
      .post<any>("http://localhost:8011/nonplussed/login", credentials, {
        observe: "response",
        headers: headers,
      })
      .subscribe((response) => {
        console.log("loging response");
        console.log(response);
        if (response?.body?.username) {
          // if (response) {
          this.authenticated = true;
        } else {
          this.authenticated = false;
        }
        return callback && callback();
      });
  }
}
