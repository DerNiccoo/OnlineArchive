# Online Archive
This project was started in 2019 together with the local voluntary fire department to advance the digitalisation of their own archive. Various content can be uploaded and then tagged to make it easier to search for specific content. For better security, different filters can be assigned to the content so that only users with the required permissions can access that content.

# Installing
Install all requirements
```
pip3 install -r requirements.txt
```

After that, it's good to set the environment variables
```
export SECRET_KEY="change_to_your_secret_key"
export FLASK_APP=archive.py
```

By default, PostgreSQL is used. If it is not already installed, you can follow [these instructions](https://opensource.com/article/17/10/set-postgres-database-your-raspberry-pi). If another database management system is used, or a different table name don't forget to change the environment variables.

After setting up PostgreSQL, create the database
```
$ psql
> create database feuerwehr;
```

Since this project uses flask migrate, the database can be easily initialized with
```
flask db init
flask db upgrade
```