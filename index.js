const storage = require('node-persist');
const readline = require('readline');
const AWS = require('aws-sdk');

const requestMFACode = () => {
  return new Promise((resolve, reject) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    rl.question('Please enter MFA code: ', code => {
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

  if (!params.roleArn) {
    throw new Error('No Role ARN provided');
  }

  const region = params.region || process.env.AWS_DEFAULT_REGION;
  const roleArn = params.roleArn;

  storage.initSync({ ttl: durationSeconds * 1000 });

  const AWS_ACCESS_KEY_ID = storage.getItemSync('AWS_ACCESS_KEY_ID');
  const AWS_SECRET_ACCESS_KEY = storage.getItemSync('AWS_SECRET_ACCESS_KEY');
  const AWS_SESSION_TOKEN = storage.getItemSync('AWS_SESSION_TOKEN');

  if (AWS_ACCESS_KEY_ID && AWS_SECRET_ACCESS_KEY && AWS_SESSION_TOKEN) {
    return Promise.resolve({
      roleArn,
      credentials: {
        accessKeyId: AWS_ACCESS_KEY_ID,
        secretAccessKey: AWS_SECRET_ACCESS_KEY,
        sessionToken: AWS_SESSION_TOKEN
      }
    });
  }

  return new AWS.IAM()
    .listMFADevices()
    .promise()
    .then(_ => _.MFADevices || [])
    .then(devices =>
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
            RoleSessionName: 'aws-assume-role',
            SerialNumber: device.SerialNumber,
            TokenCode: mfa.code,
            DurationSeconds: durationSeconds
          })
          .promise()
          .catch(_ => {
            if (_.code === 'AccessDenied' && mfa.devices.length > 0) {
              return tryToAssume(mfa.devices.pop());
            } else {
              throw _;
            }
          });
      };

      return tryToAssume(mfa.devices.pop());
    })
    .then(_ => {
      return { roleArn, credentials: {
        accessKeyId: _.Credentials.AccessKeyId,
        secretAccessKey: _.Credentials.SecretAccessKey,
        sessionToken: _.Credentials.SessionToken
      }};
    })
    .then(_ => {
      storage.setItemSync('AWS_ACCESS_KEY_ID', _.credentials.accessKeyId);
      storage.setItemSync('AWS_SECRET_ACCESS_KEY', _.credentials.secretAccessKey);
      storage.setItemSync('AWS_SESSION_TOKEN', _.credentials.sessionToken);

      return _;
    });
};
