import express from "express";
import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import * as url from "url";
import bcrypt from "bcryptjs";
import * as jwtJsDecode from "jwt-js-decode";
import base64url from "base64url";
import SimpleWebAuthnServer from "@simplewebauthn/server";

const __dirname = url.fileURLToPath(new URL(".", import.meta.url));

const app = express();
app.use(express.json());

const adapter = new JSONFile(__dirname + "/auth.json");
const db = new Low(adapter);
await db.read();
db.data ||= { users: [] };

const rpID = "localhost";
const protocol = "http";
const port = 5050;
const expectedOrigin = `${protocol}://${rpID}:${port}`;

app.use(express.static("public"));
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);

function findUser(email) {
  const users = db.data.users.filter((u) => u.email === email);
  if (users.length === 0) {
    return undefined;
  }
  return users[0];
}
// ADD HERE THE REST OF THE ENDPOINTS
app.post("/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  // TODO: Data validation

  const userFound = findUser(email);

  if (userFound) {
    res.status(200).json({ ok: false, message: "User already exists" });
  } else {
    const salt = await bcrypt.genSalt(10);
    console.log(password, salt);
    const hashedPassword = bcrypt.hashSync(password, salt);
    const user = {
      name,
      email,
      password: hashedPassword,
    };
    db.data.users.push(user);
    db.write();
    res.status(201).json({ ok: true, message: "User created." });
  }
});

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;

  const userFound = findUser(email);
  if (userFound) {
    if (bcrypt.compareSync(password, userFound.password)) {
      res.status(200).json({
        ok: true,
        name: userFound.name,
        email: userFound.email,
      });
    }
  } else {
    res.status(401).json({ message: `Invalid Credentials.` });
  }
});

app.post("/auth/login-google", (req, res) => {
  const { credential } = req.body;
  let jwt = jwtJsDecode.jwtDecode(credential);
  const { email, given_name, family_name, aud } = jwt.payload;
  let user = {
    email: email,
    name: given_name + " " + family_name,
    password: false,
  };

  const userFound = findUser(email);

  if (userFound) {
    user.federated = {
      google: aud,
    };
    db.write();
    res.status(200).json({ ok: true, name: user.name, email: user.email });
  } else {
    db.data.users.push({ ...user, federated: { google: aud } });
    db.write();
    res.status(200).json({ ok: true, name: user.name, email: email });
  }
});

app.post("/auth/options", (req, res) => {
  const { email } = req.body;
  const foundUser = findUser(email);

  if (foundUser) {
    res.status(200).json({
      password: foundUser.password !== false,
      google: foundUser.federated && foundUser.federated.google,
      webAuthn: foundUser.webAuthn,
    });
  } else {
    res.status(200).json({
      password: true,
    });
  }
});

// WebAuthn endpoints
app.post("/auth/webauth-registration-options", (req, res) => {
  const user = findUser(req.body.email);

  // options object needs to conform to webAuthn API spec as below
  const options = {
    rpName: "Coffee Masters", // reliant party i.e us/backend server
    rpID, // FQDN/domain/localhost
    userID: user.email, // visible identifier
    userName: user.name, // internal identifier
    timeout: 60000,
    attestationType: "none",

    /**
     * Passing in a user's list of already-registered authenticator IDs here prevents users from
     * registering the same device multiple times. The authenticator will simply throw an error in
     * the browser if it's asked to perform registration when one of these ID's already resides
     * on it.
     */
    excludeCredentials: user.devices
      ? user.devices.map((dev) => ({
          id: dev.credentialID,
          type: "public-key",
          transports: dev.transports,
        }))
      : [],

    authenticatorSelection: {
      userVerification: "required",
      residentKey: "required",
    },
    /**
     * The two most common algorithms: ES256, and RS256
     */
    supportedAlgorithmIDs: [-7, -257],
  };

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  const regOptions = SimpleWebAuthnServer.generateRegistrationOptions(options);
  // current challenge sent by SimpleWebAuthnServer is stored into DB because we need to verify if its the same
  // challenge or not when user answers it to /auth/webauth-registration-verification endpoint
  user.currentChallenge = regOptions.challenge;
  db.write();

  res.send(regOptions);
});

app.post("/auth/webauth-registration-verification", async (req, res) => {
  const user = findUser(req.body.user.email);
  const data = req.body.data;
  // get the stored challenge from register to check if its the same one user is responding to
  const expectedChallenge = user.currentChallenge;

  let verification;
  try {
    const options = {
      credential: data,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    };
    verification = await SimpleWebAuthnServer.verifyRegistrationResponse(
      options
    );
  } catch (error) {
    console.log(error);
    return res.status(400).send({ error: error.toString() });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    const existingDevice = user.devices
      ? user.devices.find((device) =>
          new Buffer(device.credentialID.data).equals(credentialID)
        )
      : false;
      console.log(data, 'IIIIIII')
    if (!existingDevice) {
      const newDevice = {
        credentialPublicKey,
        credentialID,
        counter,
        transports: data.response.transports,
      };
      if (user.devices == undefined) {
        user.devices = [];
      }
      user.webAuthn = true;
      user.devices.push(newDevice);
      db.write();
    }
  }

  res.send({ ok: true });
});

app.post("/auth/webauth-login-options", (req, res) => {
  const user = findUser(req.body.email);
  // if (user==null) {
  //     res.sendStatus(404);
  //     return;
  // }
  console.log(user.devices, '<<<<')
  const options = {
    timeout: 60000,
    allowCredentials: [],
    devices:
      user && user.devices
        ? user.devices.map((dev) => ({
            id: dev.credentialID,
            type: "public-key",
            transports: dev.transports,
          }))
        : [],
    userVerification: "required",
    rpID,
  };
  const loginOpts = SimpleWebAuthnServer.generateAuthenticationOptions(options);
  if (user) user.currentChallenge = loginOpts.challenge;
  res.send(loginOpts);
});

app.post("/auth/webauth-login-verification", async (req, res) => {
  const data = req.body.data;
  const user = findUser(req.body.email);
  if (user == null) {
    res.sendStatus(400).send({ ok: false });
    return;
  }

  const expectedChallenge = user.currentChallenge;

  let dbAuthenticator;
  const bodyCredIDBuffer = base64url.toBuffer(data.rawId);
  console.log(user.devices);
  for (const dev of user.devices) {
    const currentCredential = Buffer(dev.credentialID.data);
    if (bodyCredIDBuffer.equals(currentCredential)) {
      dbAuthenticator = dev;
      break;
    }
  }

  if (!dbAuthenticator) {
    return res
      .status(400)
      .send({
        ok: false,
        message: "Authenticator is not registered with this site",
      });
  }

  let verification;
  try {
    const options = {
      credential: data,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        ...dbAuthenticator,
        credentialPublicKey: new Buffer(
          dbAuthenticator.credentialPublicKey.data
        ), // Re-convert to Buffer from JSON
      },
      requireUserVerification: true,
    };
    verification = await SimpleWebAuthnServer.verifyAuthenticationResponse(
      options
    );
  } catch (error) {
    return res.status(400).send({ ok: false, message: error.toString() });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    dbAuthenticator.counter = authenticationInfo.newCounter;
  }

  res.send({
    ok: true,
    user: {
      name: user.name,
      email: user.email,
    },
  });
});

app.get("*", (req, res) => {
  res.sendFile(__dirname + "public/index.html");
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
