##########################################################################
#                                                                        #
# Author : Fabio Pinto <fabio@mandelbrot.co.za>                          #
#                                                                        #
# Description : Python Chalice based AWS API + Lambda Function for       #
#               basic User Authentication and JWT                        #
#                                                                        #
##########################################################################

#Module Imports
import boto3
import jwt
from chalice import *
from datetime import datetime, timedelta
from validate_email import validate_email
from bcrypt import hashpw, gensalt
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError

#Instantiate Chalice Application
app = Chalice(app_name='api_auth')
app.debug = True

#Instantiate DynamoDB Resources
dynamodb = boto3.resource("dynamodb", region_name='eu-west-1', endpoint_url="https://dynamodb.eu-west-1.amazonaws.com")
table_auth = dynamodb.Table('user_auth')

#JWT Secret
secret = 'noentry'

##########################################################################
#                                                                        #
# Function : email_validation(email)                                     #
#                                                                        #
# Description : Verifies the existance and validity of an email address  #
#                                                                        #
# Return : Boolean                                                       #
#                                                                        #
##########################################################################

def email_validation(email):
    if validate_email(email, verify=False) == True:
        return True
    else:
        return False

##########################################################################
#                                                                        #
# Function : user_exists(email)                                          #
#                                                                        #
# Description : Determines if the email address is already registered    #
#                                                                        #
# Return : JSON/Boolean                                                  #
#                                                                        #
##########################################################################

def user_exists(email):
    try:
        response = table_auth.query(
                KeyConditionExpression=Key('email').eq(email)
        )
        if response['Count'] > 0:
            return response
        else:
            return False
    except Exception as e:
       raise ChaliceViewError(e)

##########################################################################
#                                                                        #
# Resource : /register                                                   #
#                                                                        #
# Function : register()                                                  #
#                                                                        #
# Description : Registration of users into DynamoDB while validating     #
#               Email Addresses and Encrypting Passwords using Brcypt    #
#                                                                        #
# Return : JSON                                                          #
#                                                                        #
##########################################################################

@app.route('/register', methods=['POST'])
def register():
    request = app.current_request
    data = request.json_body

    email = data['email']

    if email_validation(email) == True:
        #Collect the rest of POST Data for registration
        try:
            first_name = data['first_name']
            last_name = data['last_name']
            password = hashpw(data['password'].encode('utf-8'), gensalt(4))
        except Exception as e:
            raise BadRequestError(e)
    else:
        raise ForbiddenError('Invalid Email Address')

    #Check if the Valid Email Already Exists
    if user_exists(email) != False:
        raise ForbiddenError('Email Adready Exists')
    else:
        #Enter details in DynamoDB Table
        try:
            response = table_auth.put_item(
                Item={
                    'email': email,
                    'first_name': first_name,
                    'last_name': last_name,
                    'password': password
                }
            )
            return {'Success': 'User Account Registered'}
        except Exception as e:
            raise ChaliceViewError(e)

##########################################################################
#                                                                        #
# Resource : /login                                                      #
#                                                                        #
# Function : login()                                                     #
#                                                                        #
# Description : Login authentication of registered users and the         #
#               provision of a JWT token with a basic payload            #
#                                                                        #
# Return : JWT                                                           #
#                                                                        #
##########################################################################

@app.route('/login', methods=['POST'])
def login():
    request = app.current_request
    data = request.json_body

    email = data['email']
    password = data['password'].encode('utf-8')

    if email_validation(email) == True:
        #Check if the Valid Email Already Exists in order to login
        response = user_exists(email)

        if response != False:
            #Compare supplied password with that of the already stored hashed password
            if hashpw(password, response['Items'][0]['password'].encode('utf-8')) == response['Items'][0]['password']:

                #Generate default token containing only expiry
                token = jwt.encode({'exp': datetime.utcnow() + timedelta(hours=1)}, secret, algorithm='HS256')

                return {'Success': 'Token Granted', 'Token': token}
            else:
                raise UnauthorizedError('Invalid Password')
        else:
            raise NotFoundError('Email is not Registered')
    else:
        raise ForbiddenError('Invalid Email Address')

##########################################################################
#                                                                        #
# Resource : /verify/{token}                                             #
#                                                                        #
# Function : verify(token)                                               #
#                                                                        #
# Description : Resource to check JWT Token validity and expiry          #
#                                                                        #
# Return : JSON                                                          #
#                                                                        #
##########################################################################

@app.route('/verify/{token}')
def verify(token):
    try:
        decoded = jwt.decode(token, secret, algorithms=['HS256'])
        return decoded
    except Exception as e:
        raise UnauthorizedError(e)

##########################################################################
#                                                                        #
# Resource : /update/{token}                                             #
#                                                                        #
# Function : update(token)                                               #
#                                                                        #
# Description : Resource to create a new token after old one is verified #
#                                                                        #
# Return : JWT                                                           #
#                                                                        #
##########################################################################

@app.route('/update/{token}', methods=['POST'])
def update(token):
    #First verify supplied token
    verify(token)

    request = app.current_request
    data = request.json_body

    #Append fresh expiry to JSON 
    data['exp'] = datetime.utcnow() + timedelta(hours=1)
    
    #Generate and return new token containing all POST data
    token = jwt.encode(data, secret, algorithm='HS256')
    return {'Success': 'Token Updated', 'Token': token}
