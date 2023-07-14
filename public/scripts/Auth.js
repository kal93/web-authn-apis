import API from "./API.js";
import Router from "./Router.js";

const Auth = {
  isLoggedIn: false,
  account: null,
  postLogin: (response, user) => {
    if (response.ok) {
      Auth.isLoggedIn = true;
      Auth.account = user;
      Auth.updateStatus();
      Router.go("/account");
    } else {
      alert(response.message);
    }
    // Credential management API storage
    // first check existance of support for credential api due to no safari support yet
    if (window.PasswordCredential && user.password) {
      // password check is for if user has logged-in from SSO/OpenID/google
      const credentials = new PasswordCredential({
        id: user.email,
        password: user.password,
        name: `WebAuthn w/s-${user.name}`,
      });
      try {
        navigator.credentials.store(credentials);
      } catch (e) {
        console.log(e);
      }
    }
  },
  register: async (event) => {
    event.preventDefault();
    const user = {
      name: document.getElementById("register_name").value,
      email: document.getElementById("register_email").value,
      password: document.getElementById("register_password").value,
    };
    console.log(user, "<<");
    const response = await API.register(user);
    console.log(response);
    Auth.postLogin(response, user);
  },
  checkAuthOptions: async (user) => {
    const response = await API.checkAuthOptions({
      email: document.getElementById("login_email").value,
    });
    console.log(response, "<<");
    Auth.loginStep = 2;
    if (response.password) {
      document.getElementById("login_section_password").hidden = false;
    }
    if (response.webAuthn) {
      document.getElementById("login_section_webauthn").hidden = false;
    }
  },
  login: async (event) => {
    if (event) {
      event.preventDefault();
    }
    if (Auth.loginStep === 1) {
      Auth.checkAuthOptions();
    } else {
      const credentials = {
        email: document.getElementById("login_email").value,
        password: document.getElementById("login_password").value,
      };
      const response = await API.login(credentials);
      console.log(response);
      Auth.postLogin(response, {
        ...credentials,
        name: response.name,
      });
    }
  },
  loginFromGoogle: async (data) => {
    console.log(data, "G+");
    const response = await API.loginFromGoogle(data);
    Auth.postLogin(response, {
      name: response.name,
      email: response.email,
    });
  },
  logout: () => {
    Auth.isLoggedIn = false;
    Auth.account = null;
    Auth.updateStatus();
    Router.go("/");
    if (window.PasswordCredential) {
      // prevent auto-login when logged out
      navigator.credentials.preventSilentAccess();
    }
  },
  autoLogin: async () => {
    if (window.PasswordCredential) {
      const credentials = await navigator.credentials.get({ password: true });
      if (credentials) {
        document.getElementById("login_email").value = credentials.id;
        document.getElementById("login_password").value = credentials.password;
        Auth.login();
        console.log(credentials);
      }
    }
  },
  updateStatus() {
    if (Auth.isLoggedIn && Auth.account) {
      document
        .querySelectorAll(".logged_out")
        .forEach((e) => (e.style.display = "none"));
      document
        .querySelectorAll(".logged_in")
        .forEach((e) => (e.style.display = "block"));
      document
        .querySelectorAll(".account_name")
        .forEach((e) => (e.innerHTML = Auth.account.name));
      document
        .querySelectorAll(".account_username")
        .forEach((e) => (e.innerHTML = Auth.account.email));
    } else {
      document
        .querySelectorAll(".logged_out")
        .forEach((e) => (e.style.display = "block"));
      document
        .querySelectorAll(".logged_in")
        .forEach((e) => (e.style.display = "none"));
    }
  },
  loginStep: 1,
  addWebAuthn: async () => {
    const options = await API.webAuthn.registrationOptions();
    console.log(options, "<<");
    options.authenticatorSelection.residentKey = "required";
    options.authenticatorSelection.requireResidentKey = true;
    options.extensions = {
      credProps: true,
    };

    const authRes = await SimpleWebAuthnBrowser.startRegistration(options);

    const verificationRes = await API.webAuthn.registrationVerification(
      authRes
    );

    if (verificationRes.ok) {
      alert(" Login with webauth");
    } else {
      alert(verificationRes.message);
    }
  },
  webAuthnLogin: async () => {
    const email = document.getElementById("login_email").value;

    const options = await API.webAuthn.loginOptions(email);

    const loginRes = await SimpleWebAuthnBrowser.startAuthentication(options);
    const verificationRes = await API.webAuthn.loginVerification(
      email,
      loginRes
    );

    if (verificationRes.ok) {
      Auth.postLogin(verificationRes, verificationRes.user);
    } else {
      alert(verificationRes.message);
    }
  },
  init: () => {
    document.getElementById("login_section_password").hidden = true;
    document.getElementById("login_section_webauthn").hidden = true;
  },
};
Auth.updateStatus();
Auth.autoLogin();

export default Auth;

// make it a global object
window.Auth = Auth;
