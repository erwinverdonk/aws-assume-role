const storage = require("node-persist");
const readline = require("readline");
const AWS = require("aws-sdk");

const requestMFACode = () => {
  return new Promise((resolve, reject) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    rl.question("Please enter MFA code: ", code => {
      if (code.length !== 6) {
        return requestMFACode();
      }

      resolve(code);
      rl.close();
    });
  });
};

exports.assumeRole = params => {
  const durationSeconds = params.durationSeconds || 3600; // 1 hour

  if (!params.region) {
    throw new Error("No region provided.");
  }

  if (!params.roleArn) {
    throw new Error("No Role ARN provided.");
  }

  const region = params.region;
  const roleArn = params.roleArn;

  storage.initSync({ ttl: durationSeconds * 1000 });

  const AWS_ACCESS_KEY_ID = storage.getItemSync("AWS_ACCESS_KEY_ID");
  const AWS_SECRET_ACCESS_KEY = storage.getItemSync("AWS_SECRET_ACCESS_KEY");
  const AWS_SESSION_TOKEN = storage.getItemSync("AWS_SESSION_TOKEN");

  if (AWS_ACCESS_KEY_ID && AWS_SECRET_ACCESS_KEY && AWS_SESSION_TOKEN) {
    process.env.AWS_ACCESS_KEY_ID = AWS_ACCESS_KEY_ID;
    process.env.AWS_SECRET_ACCESS_KEY = AWS_SECRET_ACCESS_KEY;
    process.env.AWS_SESSION_TOKEN = AWS_SESSION_TOKEN;

    AWS.config = new AWS.Config({ region });

    return Promise.resolve({
      roleArn,
      credentials: {
        AccessKeyId: AWS_ACCESS_KEY_ID,
        SecretAccessKey: AWS_SECRET_ACCESS_KEY,
        SessionToken: AWS_SESSION_TOKEN
      }
    });
  }

  return new AWS.IAM()
    .listMFADevices()
    .promise()
    .then(_ => _.MFADevices || [])
    .then(
      devices =>
        new Promise((resolve, reject) => {
          if (devices.length === 0) {
            resolve({ code: undefined, devices: [] });
            return;
          }

          requestMFACode()
            .then(code => {
              resolve({
                code,
                devices
              });
            })
            .catch(_ => reject(_));
        })
    )
    .then(mfa => {
      const sts = new AWS.STS();

      const tryToAssume = device => {
        return sts
          .assumeRole({
            RoleArn: roleArn,
            RoleSessionName: "aws-assume-role",
            SerialNumber: device.SerialNumber,
            TokenCode: mfa.code,
            DurationSeconds: durationSeconds
          })
          .promise()
          .catch(_ => {
            if (_.code === "AccessDenied" && mfa.devices.length > 0) {
              return tryToAssume(mfa.devices.pop());
            } else {
              throw _;
            }
          });
      };

      return tryToAssume(mfa.devices.pop());
    })
    .then(_ => {
      return { roleArn, credentials: _.Credentials };
    })
    .then(_ => {
      process.env.AWS_ACCESS_KEY_ID = _.credentials.AccessKeyId;
      process.env.AWS_SECRET_ACCESS_KEY = _.credentials.SecretAccessKey;
      process.env.AWS_SESSION_TOKEN = _.credentials.SessionToken;

      AWS.config = new AWS.Config();

      storage.setItemSync("AWS_ACCESS_KEY_ID", _.credentials.AccessKeyId);
      storage.setItemSync(
        "AWS_SECRET_ACCESS_KEY",
        _.credentials.SecretAccessKey
      );
      storage.setItemSync("AWS_SESSION_TOKEN", _.credentials.SessionToken);

      return _;
    });
};
