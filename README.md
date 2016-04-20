# Heroku Deployment
This repository has all the base files ready for deploying a Heroku application.

### Usage

```bash
$ git clone https://github.com/sharadvishe/lrsapis.git
$ cd lrsapis
$ heroku create
$ git push heroku master
```

### Running web application locally
```bash
$ git clone https://github.com/sharadvishe/lrsapis.git
$ cd lrsapis
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ python app.py
```

### NOTE :
	Add config.py file in lrsapis/ folder which will hold mongodb credentials as below:

#####	
    MONGODB_SETTINGS = {
       'db': {dbname},
       'host' : 'mongodb://{username}:{password}@{host}:{port}/{dbname}'
    }






