import Vue from "vue";
import Cookies from "js-cookie";

class Authenticate {
  constructor() {
    this._options = {
      base_url: null,
      client_id: null,
      service_name: "password-auth",
      token_endpoint: null,
      token_type: "Bearer",
      token_header: "Authorization",
      userinfo_endpoint: null,
      cookie_secure: false
    };
    this._store = new Vue({
      data: {
        isAuthenticated: false,
        user: {}
      }
    });
    this._refreshTimer = null;
  }

  install(Vue, options) {
    this._options = Object.assign({}, this._options, options);
    const vm = this;

    Vue.prototype.$passwordAuth = {
      authenticate: this.authenticate.bind(this),
      reloadState: this.refreshStoreState.bind(this),
      get isAuthenticated() {
        return vm._store.isAuthenticated;
      },
      get user() {
        return vm._store.user;
      },
      get store() {
        return vm._store.$data;
      }
    };

    this.setAxiosBinding();
    this.refreshStoreState();
    this.setRefreshTimer();
  }

  getAccessToken() {
    return Cookies.get(this._options.service_name);
  }

  refreshStoreState() {
    // 1. Check cookie existence
    // No need to check expires since we set in cookie's expires itself
    const accessToken = this.getAccessToken();

    if (accessToken) {
      this._store.isAuthenticated = true;

      if (Object.keys(this._store.user).length === 0) {
        Vue.prototype.$http
          .get(this._options.base_url + this._options.userinfo_endpoint)
          .then(response => {
            this._store.user = response.data;
          });
      }
    } else {
      this._store.isAuthenticated = false;
      this._store.user = {};
    }
  }

  authenticate({ client_id, username, password }) {
    return Vue.prototype.$http
      .post(this._options.base_url + this._options.token_endpoint, {
        client_id,
        username,
        password
      })
      .then(response => {
        const { token_type, expires_in, access_token } = response.data;

        // 1. Save to cookie
        // - set secure
        // - set expiry
        const expiryDate = new Date(
          new Date().getTime() + parseInt(expires_in, 10) * 1000
        );

        Cookies.set(this._options.service_name, access_token, {
          expires: expiryDate,
          secure: this._options.cookie_secure
        });

        Cookies.set(
          `${this._options.service_name}-expiry`,
          expiryDate.getTime(),
          {
            expires: expiryDate,
            secure: this._options.cookie_secure
          }
        );

        this.refreshStoreState();
        this.setRefreshTimer();
      })
      .catch(err => {
        throw new Error(err.response.data.message);
      });
  }

  setAxiosBinding() {
    const vm = this;

    if (!Vue.prototype.$http) {
      try {
        const axios = require("axios");
        const VueAxios = require("vue-axios");
        Vue.use(VueAxios, axios);
      } catch (err) {
        console.warn(
          "[WARN] Vue axios not found. Please install `vue-axios` package first."
        );
      }
    }

    Vue.prototype.$http.interceptors.response.use(
      response => response,
      error => {
        // If url = base url and unauthorized, switch authenticated back to false
        const url = new URL(error.config.url);
        if (
          url.origin === vm._options.base_url &&
          error.response.status === 401 &&
          vm._store.isAuthenticated
        ) {
          Cookies.remove(vm._options.service_name);
          vm.refreshStoreState();
        }
        return Promise.reject(error);
      }
    );

    Vue.prototype.$http.interceptors.request.use(function(config) {
      const url = new URL(config.url);

      // If url = base url and authenticated, set the authorization header
      if (url.origin === vm._options.base_url && vm._store.isAuthenticated) {
        config.headers[vm._options.token_header] = `${
          vm._options.token_type
        } ${vm.getAccessToken()}`;
      }

      return config;
    });
  }

  setRefreshTimer() {
    if (this._refreshTimer) clearTimeout(this._refreshTimer);

    const expiryTime = parseInt(
      Cookies.get(`${this._options.service_name}-expiry`),
      10
    );

    this._refreshTimer = setTimeout(
      () => this.refreshStoreState(),
      expiryTime + 1000 - new Date().getTime()
    );
  }
}

export default new Authenticate();
