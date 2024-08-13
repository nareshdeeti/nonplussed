import { HttpClient, HttpParams, HttpHeaders } from "@angular/common/http";
import { Component } from "@angular/core";
import {
  FormGroup,
  FormBuilder,
  FormControl,
  ReactiveFormsModule,
  FormsModule,
} from "@angular/forms";
import { Router } from "@angular/router";
import { AuthenticationService } from "../authentication.service";

@Component({
  selector: "app-login",
  standalone: true,
  imports: [ReactiveFormsModule, FormsModule],
  templateUrl: "./login.component.html",
  styleUrl: "./login.component.scss",
})
export class LoginComponent {
  loginForm!: FormGroup;
  csrfToken: string = "";

  constructor(
    private formBuilder: FormBuilder,
    private http: HttpClient,
    private router: Router,
    private auth: AuthenticationService,
  ) {
    this.buildForm();
    this.http
      .get<any>("http://localhost:8011/nonplussed/csrf")
      .subscribe((response) => {
        this.csrfToken = response.token;
        window.localStorage.setItem("csrfToken", this.csrfToken);
        console.log("csrfToken: " + this.csrfToken);
      });
  }

  private buildForm() {
    this.loginForm = this.formBuilder.group({
      username: new FormControl(),
      password: new FormControl(),
    });
  }

  login() {
    const creds = this.loginForm.value;
    this.auth.authenticate(creds, () => {
      this.router.navigateByUrl("/home");
    });

    /* const httpParams = new HttpParams();
    httpParams.set("username", creds['username']);
    httpParams.set("password", creds['password']);

    const headers = new HttpHeaders({'Content-Type': 'application/x-www-form-urlencoded'});
    this.http.post("http://localhost:8011/nonplussed/login", headers, {observe: "body"})
    .subscribe(res => console.log(res)); */
  }
}
