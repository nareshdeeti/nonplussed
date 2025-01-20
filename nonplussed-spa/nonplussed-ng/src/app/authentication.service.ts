import {HttpClient, HttpHeaders} from "@angular/common/http";
import {inject, Injectable} from "@angular/core";
import { Router } from "@angular/router";

@Injectable({providedIn: "root"})
export class AuthenticationService {
  // private isAuthenticatedSubject = new BehaviorSubject<boolean | null>(null);
  authenticated = false;
  http: HttpClient = inject(HttpClient);
  router: Router = inject(Router);

  authenticate(credentials: any) {
    this.http
      .post<any>("http://localhost:8011/users/login", {
        "username": credentials.username,
        "password": credentials.password
      }, {
        observe: "response",
      })
      .subscribe((response: any) => {
        if (response?.body?.username) {
          this.authenticated = true;
          this.router.navigateByUrl("/home");
        } else {
          this.authenticated = false;
          this.router.navigateByUrl("/login");
        }
      });
  }

}
