import { HttpClient } from "@angular/common/http";
import { Component } from "@angular/core";

@Component({
  selector: "app-home",
  standalone: true,
  imports: [],
  templateUrl: "./home.component.html",
  styleUrl: "./home.component.scss",
})
export class HomeComponent {

  username: string = '';

  constructor(private http: HttpClient) {
    http.get<any>("http://localhost:8011/users/me", {observe: 'response'})
      .subscribe((res) => this.username = res.body.username);
  }

}
