const storage = require('node-persist');
const readline = require('readline');
const AWS = require('aws-sdk');

const requestMFA = () => {
  const promptForMFACode = () => new Promise((resolve, reject) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    rl.question('Please enter MFA code: ', code => {
      if (code.length !== 6) {
        return promptForMFACode();
      }

      resolve(code);
      rl.close();
    });
  });

  return new AWS.IAM()
    .listMFADevices()
    .promise()
    .then(_ => _.MFADevices || [])
    .then(devices => new Promise((resolve, reject) => {
      if (devices.length === 0) {
        resolve({ code: undefined, devices: [] });
        return;
      }

      promptForMFACode()
        .then(code => {
          resolve({
            code,
            devices
          });
        })
        .catch(_ => reject(_));
    })
  );
};

const getStoredCredentials = () => {
  const accessKeyId = storage.getItemSync('AWS_ACCESS_KEY_ID');
  const secretAccessKey = storage.getItemSync('AWS_SECRET_ACCESS_KEY');
  const sessionToken = storage.getItemSync('AWS_SESSION_TOKEN');

  return Promise.resolve(
    accessKeyId && secretAccessKey && sessionToken
      ? { accessKeyId, secretAccessKey, sessionToken }
      : undefined
  );
};

const setStoredCredentials = credentials => {
  storage.setItemSync('AWS_ACCESS_KEY_ID', credentials.accessKeyId);
  storage.setItemSync('AWS_SECRET_ACCESS_KEY', credentials.secretAccessKey);
  storage.setItemSync('AWS_SESSION_TOKEN', credentials.sessionToken);

  return Promise.resolve(credentials);
};

const requestTemporaryCredentials = (roleArn, durationSeconds) => requestMFA()
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
  .then(_ => ({
    credentials: {
      accessKeyId: _.Credentials.AccessKeyId,
      secretAccessKey: _.Credentials.SecretAccessKey,
      sessionToken: _.Credentials.SessionToken
    }
  }))
  .then(_ => {
    return setStoredCredentials(_.credentials);
  });

exports.assumeRole = params => {
  if (!params.roleArn) {
    throw new Error('No Role ARN provided');
  }

  const durationSeconds = params.durationSeconds || 3600; // 1 hour
  const region = params.region || process.env.AWS_DEFAULT_REGION;
  const roleArn = params.roleArn;

  if (!region) {
    throw new Error('No region provided');
  }

  storage.initSync({ ttl: durationSeconds * 1000 });

  return getStoredCredentials()
    .then(_ => !_ ? requestTemporaryCredentials(roleArn, durationSeconds) : _);
};
