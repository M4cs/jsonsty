<p align="center">
    <a href="https://github.com/kognise/water.css"><img src="https://github.com/kognise/water.css/raw/master/logo.svg?sanitize=true" width="25%"></a><a href=""><img src="https://upload.wikimedia.org/wikipedia/commons/thumb/3/3c/Flask_logo.svg/1200px-Flask_logo.svg.png" width="25%;">
    <br>
    <img src="https://github.com/M4cs/jsonsty/blob/master/banner.png?raw=true">
    <br>
    <b>Made with Python and Flask</b>
    <br>
    <a href="https://github.com/M4cs/jsonsty/stargazers"><img src="https://img.shields.io/github/stars/M4cs/jsonsty"></a>
    <a href="https://github.com/M4cs/jsonsty/issues"><img src="https://img.shields.io/github/issues/M4cs/jsonsty"></a>
    <a href="https://github.com/M4cs/jsonsty/forks"><img src="https://img.shields.io/github/forks/M4cs/jsonsty"></a>
    <a href=""><img src="https://img.shields.io/github/license/M4cs/jsonsty"></a>
    <img src="https://img.shields.io/badge/python-3.6%2B-green">
</p>

# JSONsty

What is JSONsty? JSONsty is a service provided by [psty.io](https://psty.io) that allows you to store JSON data in the cloud for free using an extremely simple API or web panel frontend. The source code here includes everything running on the [website](https://json.psty.io) as we speak. It should always be 1:1 up-to-date on the `master` branch compared to the website.

# How Does It Work?

JSONsty is a Flask application that includes a REST API and dynamically rendered Website using the Jinja2 module. It interfaces and stores all data on a remote mongoDB cluster that acts as the master database. Users have an account which links the data, known as `stores`, on the database, and then link said store to the user.

When you create an account you receive an API Key which allows you to communicate with our API. The API allows you to create, edit, grab, and delete stored JSON data on our servers. The website is a graphical version of the API which offers all functionality the API does, and more. The more comes from the ability to live edit and replace stores of data. It also allows you to change certain account settings, like regenerating API keys, that the API does not alone.

# Getting Started

To get started as a user, signup on the [website here](https://json.psty.io) and login to your account. When you login to your account and go to `Account Settings` you will see your API Key:

<p align="center"><img src="https://github.com/M4cs/jsonsty/blob/master/examples/api_key_example.png?raw=true"></p>

This will be your token for Authenticating with the JSONsty API. More info on the API can be found [here on the documentation page](https://json.psty.io).

# JSONsty's Development

JSONsty was written in Python using the Flask framework. The development enviroment is pretty simple to setup. Poetry is used for dependency management and for a virtual env. You can install `poetry` by running `pip install poetry`. You will have to be on the first stable release or higher though as that's what this was built with. 

To run the development environment first make sure you setup a `.config.json` file with your credentials for a test database. An example `.config.json` looks like this:

```json
{
    "MONGO_URI": "<MONGO_URI>",
    "TEST_MONGO_URI": "<MONGO_URI>",
    "SECRET_KEY": "<SECRET_KEY>",
    "RECAPTCHA_ENABLED": false,
    "RECAPTCHA_SITE_KEY": "",
    "RECAPTCHA_SECRET_KEY": ""
}
```

**Make sure to set RECAPTCHA_ENABLED to False or you will run into issues with reCaptcha verification.** You will also need to be hosting your own mongoDB node. You can register [here](https://mongodb.com) and get a free 520MB cluster to test with or use in your own projects. You can also run mongoDB locally but you'll need to generate the connection URI correctly.

To run the development server run the following commands:

```
# On *nix
chmod +x prepare-testing.sh
./prepare-testing.sh

# On Windows
prepare-testing.bat
```

This will setup the test_app correctly for you and will also use the `TEST_MONGO_URI` value from your `.config.json`.

# Contributing

Any and all PRs are welcomed and appreciated. When contributing make sure to keep in mind that we are using `poetry` to version control this project. Please make sure to update your `poetry.lock` file when adding new dependencies and make note in any PRs of those types of additons. 

# License

Licensed under MIT 2019 Max Bridgland <psty.io>
