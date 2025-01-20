import {ApplicationConfig, provideZoneChangeDetection,} from "@angular/core";
import {provideRouter} from "@angular/router";

import {routes} from "./app.routes";
import {provideHttpClient, withInterceptors, withInterceptorsFromDi,} from "@angular/common/http";
import {withCredentialsInterceptor} from "./api.interceptor";

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideHttpClient(
      withInterceptorsFromDi(),
      withInterceptors([withCredentialsInterceptor])
    ),
    provideZoneChangeDetection({ eventCoalescing: true })
  ],
};
