const AmazonCognitoIdentity = require("amazon-cognito-identity-js");
const Joi = require("joi");
global.fetch = require("node-fetch");

const header =  {
  'Access-Control-Allow-Origin': '*',
  'Content-Type': 'application/json'},

const poolData = {
  UserPoolId: "ap-south-1_PEwtB928L",
  ClientId: "6beln9ccc93keku7u2f1i3vjgi",
};

const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

function validateRegistrationForm(user) {
  const schema = {
    name: Joi.string().required().min(5).max(50),
    email: Joi.string().required().min(5).max(255).email(),
    password: Joi.string().required().min(5).max(255),
  };
  return Joi.validate(user, schema);
}

module.exports.register = async (event) => {
  const user = JSON.parse(event.body);
  const { error } = validateRegistrationForm(user);
  if (error) {
    return {
      statusCode: 400,
      headers:header,
      body: JSON.stringify(error.details[0]),
    };
  }

  const emailData = {
    Name: "email",
    Value: user.email,
  };
  const phoneData = {
    Name: "phone_number",
    Value: user.contactNumber,
  };
  const nameData = {
    Name: "name",
    Value: user.name,
  };

  const emailAttribute = new AmazonCognitoIdentity.CognitoUserAttribute(
    emailData
  );
  const phoneAttribute = new AmazonCognitoIdentity.CognitoUserAttribute(
    phoneData
  );
  const nameAttribute = new AmazonCognitoIdentity.CognitoUserAttribute(
    nameData
  );

  try {
    const register = await new Promise((resolve, reject) => {
      userPool.signUp(
        user.email,
        user.password,
        [emailAttribute, phoneAttribute, nameAttribute],
        null,
        (err, data) => {
          if (err) {
            reject(err);
          }
          resolve(data);
        }
      );
    });

    return {
      statusCode: 200,
      headers:header,
      body: JSON.stringify({
        message: "successfully added",
        data: register.user,
      }),
    };
  } catch (error) {
    return {
      statusCode: 422,
      headers:header,
      body: JSON.stringify({
        message: error.message,
        success: false,
      }),
    };
  }
};

function validateLoginForm(user) {
  const schema = {
    email: Joi.string().required().min(5).max(255).email(),
    password: Joi.string().required().min(5).max(255),
  };

  return Joi.validate(user, schema);
}

module.exports.login = async (event) => {
  const user = JSON.parse(event.body);

  const { error } = validateLoginForm(user);
  if (error) {
    return {
      statusCode: 400,
      headers:header,
      body: JSON.stringify(error.details[0]),
    };
  }

  const authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(
    {
      Username: user.email,
      Password: user.password,
    }
  );

  const cognitoUser = new AmazonCognitoIdentity.CognitoUser({
    Username: user.email,
    Pool: userPool,
  });

  try {
    const result = await new Promise((resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess(data) {
          resolve(data);
        },
        onFailure(error) {
          reject(error);
        },
      });
    });

    return {
      statusCode: 200,
      headers:header,
      body: JSON.stringify(result),
    };
  } catch (error) {
    return {
      statusCode: 401,
      headers:header,
      body: JSON.stringify({
        message: error.message,
        success: false,
      }),
    };
  }
};
