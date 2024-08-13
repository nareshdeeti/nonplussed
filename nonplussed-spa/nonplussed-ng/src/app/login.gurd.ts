/* import {
  CanLoad,
  Router
} from '@angular/router';
import { map, Observable, take } from 'rxjs';
import { AuthenticationService } from './authentication.service';

export class LoginGuard implements CanLoad {
  constructor(
    private router: Router,
    private autenticationService: AuthenticationService
  ) {}

  canLoad(): Observable<boolean> {
    return this.autenticationService.isAuthenticated.pipe(
      take(1),
      map((isAuthenticated) => {
        if (isAuthenticated) {
          this.router.navigateByUrl('/welcome', { replaceUrl: true });
          return false;
        }
        return true;
      })
    );
  }
}
 */
