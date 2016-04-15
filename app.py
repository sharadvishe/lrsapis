#!/usr/bin/env python
import os
from flask import  Flask, abort, request, jsonify, g, url_for,render_template
import requests
import json
import datetime
import collections
from models.models import *
from flask.ext.mongoengine import MongoEngine
from flask.ext.mongoengine.wtf import model_form
from flask.ext.cors import CORS

from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

# initialization
app = Flask(__name__)
CORS(app)
app.config.from_object('config')
mongoDb = MongoEngine(app)
mongoDb.connect()


app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})

def convert(data):
    if isinstance(data, basestring):
        return str(data)
    elif isinstance(data, collections.Mapping):
        return dict(map(convert, data.iteritems()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(convert, data))
    else:
        return data

@app.route('/')
@app.route('/statastic')
def stat():
    return render_template('statastic.html')    

@app.route('/processes')
def index():
    log = json.loads((get_gateway_status()).data)
    log = json.loads(log['data'])
    logs = []
    for data in log:
        # data['timestamp'] = datetime.datetime.fromtimestamp(data['timestamp']).strftime('%d-%m-%Y %H:%M:%S')
        # print data['timestamp']
        logs.append(data)
    return render_template('index.html',log=logs)


@app.route('/lrs/api/v1.0/gateway/status', methods=['GET'])
def get_gateway_status():    
    status = GatewayStatus.objects.all().order_by('-timestamp')
    return jsonify(data=status.to_json())
    

@app.route('/lrs/api/v1.0/gateway/status', methods=['POST'])
@auth.login_required
def set_gateway_status():

    vm =  request.json['memory']['virtual_memory']
    sm =  request.json['memory']['swap_memory']
    ni =  request.json['network']['network_info']
    ci =  request.json['cpu']['cpu_info']
    virtual_memory = VirtualMemory(**vm)
    swap_memory = SwapMemory(**sm)
    network_info = NetworkInfo(**ni)
    cpu_info = CpuInfo(**ci)
    memory = Memory(virtual_memory=virtual_memory,swap_memory=swap_memory)
    network = Network(network_info=network_info)
    cpu = Cpu(cpu_info=cpu_info)
    gs = GatewayStatus(memory=memory,network=network,cpu=cpu,timestamp=request.json['timestamp'])
    gs.save() 

    return jsonify(data=gs.to_json())

@app.route('/lrs/api/v1.0/statastic', methods=['GET'])
# @auth.login_required
def statastic():    
    status = Statastic.objects.all().order_by('-timestamp')
    return status.to_json()       


@app.route('/lrs/api/v1.0/statastic', methods=['POST'])
@auth.login_required
def set_statastic():    
    data = request.json
    prev = Statastic.objects(device_id=data['device_id']).order_by('-timestamp')[:1]

    if "temperature" in data:
        temperature = data['temperature']
    else:
        print "temperature is not exists"
        temperature = 0

    if "device_id" in data:
        device_id = data['device_id']
    else:
        print "dummy device id"
        device_id = "00:00:00:XX"

    print "device is:"+device_id           


    if len(prev) == 0:
        print "in if loop"
        pass
    else: 
        print "in else loop"           
        prev = json.loads((prev[0]).to_json())
        print prev['firmware_status']
        print data['firmware_status']
        if prev['firmware_status'] == data['firmware_status']:
            print "in elseif"
            s = Statastic.objects(id=prev['_id']['$oid']).delete()
            print "object delete successfully"
    print"create new object"        

    stat = Statastic(device_id=data['device_id'],timestamp=data['timestamp'],boot_time=data['boot_time'],cpu_utilization=data['cpu_utilization'],mem_utilization=data['mem_utilization'],uptime=data['uptime'],firmware_status=data['firmware_status'],temperature=temperature)
    stat.save()
    return json.dumps(data)        


@app.route('/lrs/api/v1.0/gateway_internal', methods=['GET'])
def get_process_status():    
    status = ProcessInfo.objects.all()
    return status.to_json()

@app.route('/lrs/api/v1.0/gateway_internal', methods=['POST'])
@auth.login_required
def set_process_status():

    data = request.json
    count = 0
    try:
        for p in data:            
            process_info = ProcessInfo(pid=p['pid'],cpu=p['cpu'],memory=p['memory'],status=p['status'],name=p['name'],nice=p['nice'])
            process_info.save()
            print "Object saved"
    except:
        print "Exception"
    else:
        "run successfully"       
    
    return count

@app.route('/lrs/api/v1.0/gateway/internet/log', methods=['POST'])
def internet_log():
    data = request.json
    log = InternetLog(device_id=data['device_id'],from_timestamp=data['from_timestamp'],to_timestamp=data['to_timestamp'],status=data['status'])
    log.save()
    return json.dumps(data)

@app.route('/internet/log/<string:device_id>',methods=['GET'])
def show_log(device_id):
    # data = request.json
    # import pdb;pdb.set_trace()
    data = InternetLog.objects(device_id=device_id).order_by('-from_timestamp')
    return render_template('internet_log.html',data=data)   

if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()

    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)        
    # app.run(debug=True)
