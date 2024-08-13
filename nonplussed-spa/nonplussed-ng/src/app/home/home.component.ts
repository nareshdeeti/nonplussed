import { HttpClient, HttpHeaders, HttpParams } from "@angular/common/http";
import { Component } from "@angular/core";
import { LoginComponent } from "../login/login.component";
import { AuthenticationService } from "../authentication.service";

@Component({
  selector: "app-home",
  standalone: true,
  imports: [],
  templateUrl: "./home.component.html",
  styleUrl: "./home.component.scss",
})
export class HomeComponent {
  constructor(private http: HttpClient) {

    /* let headers = new HttpHeaders();
    headers.set('X-XSRF-TOKEN', AuthenticationService.csrfToken); */
    let params = new HttpParams();
    params.set('_csrf', AuthenticationService.csrfToken);
    console.log("csrf " + window.localStorage.getItem('csrfToken'));

    http
      // .get("http://localhost:8011/nonplussed/logged-user?_csrf="+window.localStorage.getItem('csrfToken'))
      // .get("http://localhost:8011/nonplussed/logged-user", {withCredentials: true})
      .get("http://localhost:8011/nonplussed/logged-user")

      .subscribe((res) => console.log(res));
  }
}
