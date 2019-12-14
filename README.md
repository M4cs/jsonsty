# Development

You will need to connect a development database to your project. I will not be providing a development db to save on space so you should be able to host one yourself or just get a free one from mongodb.com.

Create a `.config.json` file in the root of the project.

Template for said file is as follows:

```json
{
    "MONGO_URI": "MONGO_URI",
    "TEST_MONGO_URI": "MONGO_URI",
    "SECRET_KEY": "SECRET_KEY"
}
```

You will want to set your TEST_MONGO_URI as your test database and then run either `prepare-testing.sh` or `prepare-testing.bat`

```
pip3 install poetry
poetry install
poetry run server
```

This will run the application for you. To run unittests run the following command:

```
python -m unittest
```

This will run tests inside `test_app`.
