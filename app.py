from flask import Flask, jsonify, request, render_template,make_response
from flask_restful import Api, Resource
from flask_cors import CORS
from models import db,Expense,Item,User,Quote,QuoteItem,DeliveryNote,DeliveryNoteItem,RevokedToken,UnfitRetreadtyre,BankAccount,CreditNote,BalanceSheet,CashBook,CashBookDebit,TradingProfitLossAccount,CreditNoteItem,PumpFueling,VehicleMaintananceItem,VehicleMantainance,ShopRetread,RetreadTyreTrip,RetreadTyreTripItem,PumpName,PumpUpdate,SpareCategory,SpareSubCategory,Deposit,BankItem,Funds,AccountCategory,AccountType,RetreadedTyre,Total,NewBill, NewBillItem,Store,StockItem, Update,Vendor, Tyre,PaymentMade,Removetyre, TransactionReceived,Customer,Purchase,RemoveRetreadtyre, NewInvoice, NewInvoiceItem,RetreadTyre, RetreadTyreupdate,Truck, OldTyres, FitUsedTyre,TransactionReceivedInvoices, PaymentMadeBill
from flask_migrate import Migrate
from datetime import datetime
from flask_jwt_extended import JWTManager, create_access_token,create_refresh_token, get_jwt_identity,jwt_required, get_jwt
from sqlalchemy.orm import sessionmaker, session
from sqlalchemy import or_, case
from werkzeug.security import check_password_hash,generate_password_hash
import re
from flask_mail import Mail,Message
from sqlalchemy import and_
import os
from flask_cors import cross_origin
from flask_bcrypt import Bcrypt
from flask import session
from datetime import timedelta


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.json.compact = False

CORS(app, supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])

migrate = Migrate(app, db)

db.init_app(app)

api = Api(app)

bcrypt = Bcrypt(app)

# Configure secret keys
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default_jwt_secret_key')

# Initialize JWTManager
jwt = JWTManager(app)

# Refresh Token
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=13)  # Access token expires in 1 hour
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=15)


email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'


class UserRegister(Resource):
    @cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
    def post(self):
        data = request.get_json()

        # Print incoming data for debugging
        print("Received data:", data)

        username = data.get('username')
        email = data.get('email')
        phone_number = data.get('phone_number')
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        # Ensure the password and confirm_password are strings
        password = str(password)
        confirm_password = str(confirm_password)

        # Validate input data
        if not username or not email or not phone_number or not password:
            return jsonify({'error': 'Missing required fields'}), 400

        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'User already exists'}), 409

        # Hash the password
        hashed_pw = generate_password_hash(password)  # Ensure hashed password is a string

        # Create new user
        new_user = User(
            username=username,
            email=email,
            phone_number=phone_number,
            password=hashed_pw
        )

        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

        return jsonify({
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "phone_number": new_user.phone_number
        }), 201

api.add_resource(UserRegister, '/userRegister', endpoint='register')

class UserLogin(Resource):
    @cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
    def post(self):
        data = request.get_json(force=True)

        username = data.get('username')
        password = data.get('password')

        # Check if both username and password are provided
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        # If user not found or password does not match
        if user is None or not check_password_hash(user.password, password):
            return jsonify({'error': 'Unauthorized, incorrect username or password'}), 401

        # Generate access token with user ID included
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        # Create a response and set tokens in httpOnly cookies
        response = make_response({"message": "Login successful"})
        response.set_cookie('access_token', access_token, httponly=True, secure=True, samesite='Strict')
        response.set_cookie('refresh_token', refresh_token, httponly=True, secure=True, samesite='Strict')

        # Return user details and token
        return jsonify({
            "id": user.id,
            "username": user.username,
            "access_token": access_token,
            "refresh_token": refresh_token
        }), 201

# Adding the resource to the API
api.add_resource(UserLogin, '/userLogin')

class CheckSession(Resource):
    @cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
    @jwt_required(optional=True)  # Allow access without token but handle it explicitly
    def get(self):
        # Retrieve user ID from token if present
        user_id = get_jwt_identity()
        
        if not user_id:
            # Respond with 401 Unauthorized for clients to redirect
            return {'message': '401: Unauthorized - Login Required'}, 401
        
        # Fetch the user by ID
        user = User.query.filter(User.id == user_id).first()
        
        if user:
            return user.to_dict(), 200
        else:
            return {'message': '401: User not found'}, 401

# Add the resource to the API
api.add_resource(CheckSession, '/check_session')


class UserLogout(Resource):
    @jwt_required()
    @cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
    def post(self):
        # Revoke the token
        jti = get_jwt()['jti']
        revoked_token = RevokedToken(jti=jti)
        
        # Check if the token is already revoked
        existing_token = RevokedToken.query.filter_by(jti=jti).first()
        if existing_token:
            return jsonify(message="Token already revoked."), 200

        db.session.add(revoked_token)
        db.session.commit()

        # Clear the cookies
        response = make_response(jsonify(message="Logged out successfully"), 200)
        response.set_cookie('access_token', '', expires=0)
        response.set_cookie('refresh_token', '', expires=0)

        return response

# Add the logout resource to the API
api.add_resource(UserLogout, '/logout')

class TokenRefresh(Resource):
    @jwt_required(refresh=True)
    @cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
    def post(self):
        current_user_id = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user_id)

        return {"access_token": new_access_token}, 200

    
api.add_resource(TokenRefresh, '/tokenrefresh')

class TokenRevocation(Resource):
    @jwt_required()
    @cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
    def post(self):
        jti = get_jwt()['jti']  # Get JWT ID from the current token
        revoked_token = RevokedToken(jti=jti)
        db.session.add(revoked_token)
        db.session.commit()
        return jsonify(message='Token has been revoked'), 200


class UserDetails(Resource):
    @jwt_required()
    @cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
    def get(self):
        current_user_id = get_jwt_identity()

        # Fetch the user by the current_user_id
        user = User.query.filter_by(id=current_user_id).first()

        # Check if user exists
        if not user:
            return {"message": "User not found"}, 404

        # Convert the user object to a dictionary
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "phone_number": user.phone_number
        }

        return {"user": user_data}, 200

    @jwt_required()
    @cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
    def patch(self):
        current_user_id = get_jwt_identity()

        # Fetch the user by the current_user_id
        user = User.query.filter_by(id=current_user_id).first()

        # Check if user exists
        if not user:
            return {"message": "User not found"}, 404

        # Get the data from the request
        data = request.get_json()

        # Validate the incoming data
        allowed_fields = ['username', 'email', 'phone_number']
        for field in data:
            if field not in allowed_fields:
                return {"error": f"'{field}' is not a valid field."}, 400

        # Update only the fields provided in the request
        if 'username' in data and data['username']:
            user.username = data['username']
        if 'email' in data and data['email']:
            user.email = data['email']
        if 'phone_number' in data and data['phone_number']:
            user.phone_number = data['phone_number']

        try:
            db.session.commit()
            # Return the updated user data
            updated_user_data = {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "phone_number": user.phone_number
            }
            return {"user": updated_user_data}, 200
        except Exception as e:
            db.session.rollback()
            return {"error": f"Failed to update user: {str(e)}"}, 500

# Add the resource route
api.add_resource(UserDetails, '/userdetails')


@app.route('/items', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_items():    
    
    if request.method == 'GET':  
        item_details = request.args.get('item_details')

        if item_details:
            # Perform search by name
            inventory_items = Item.query.filter(Item.item_details.ilike(f'%{item_details}%')).all()
        else:
            # If no search term provided, return all items
            inventory_items = Item.query.all()

        return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200
        
    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        # Input validation
        required_fields = ['item_details', 'quantity','price']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        item_details = data.get('item_details')
        quantity = data.get('quantity')
        price = data.get('price')

        
        # Convert date string to Python date object
        # date_str = data.get('date')
        # date = datetime.strptime(date_str, '%Y-%m-%d').date()

        new_spare_item = Item(
            item_details=item_details,
            quantity=quantity,
            price=price,
        )

        try:
            db.session.add(new_spare_item)
            db.session.commit()
            return jsonify(new_spare_item.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500


@app.route('/items/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_items_by_id(id):
    session = db.session()
    purchase = session.get(Item, id)

    if request.method == 'GET':
        if not purchase:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(purchase.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not purchase:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400


        for key, value in data.items():
            setattr(purchase, key, value)

        try:
            db.session.commit()
            return jsonify(purchase.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500
        
@app.route('/trucks', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_trucks():
    if request.method == "GET":
        inventory_items = Truck.query.all()
        return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        required_fields = ['truck_number', 'driver', 'vehicle_type']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
            
        truck_number = data.get('truck_number')
        driver = data.get('driver')
        vehicle_type = data.get('vehicle_type')
        manufacturer = data.get('manufacturer')
        vehicle_id = data.get('vehicle_id')
        trailer = data.get('trailer')
        contact = data.get('contact')

        new_truck = Truck(
            truck_number = truck_number,
            driver = driver,
            vehicle_type = vehicle_type,
            manufacturer = manufacturer,
            vehicle_id = vehicle_id,
            trailer=trailer,
            contact=contact,
        )
        try:
            db.session.add(new_truck)
            db.session.commit()
            return jsonify(new_truck.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Truck: {str(e)}'}), 500
        
@app.route('/trucks/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_trucks_by_id(id):
    
    truck = Truck.query.filter_by(id=id).first()

    if request.method == 'GET':
        if not truck:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(truck.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not truck:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

        for key, value in data.items():
            setattr(truck, key, value)

        try:
            db.session.commit()
            return jsonify(truck.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update truck: {str(e)}'}), 500

    elif request.method == 'DELETE':
        if not truck:
            return jsonify({'error': 'Item not found'}), 404
        
        try:
            db.session.delete(truck)
            db.session.commit()
            return jsonify({'message': 'Truck deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete truck: {str(e)}'}), 500

        
@app.route('/customers', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_customers():
    if request.method == "GET":
        customer_name = request.args.get('customer_name')

        if customer_name:
            # Perform search by name
            customers = Customer.query.filter(Customer.customer_name.ilike(f'%{customer_name}%')).all()
        else:
            # If no search term provided, return all items
            customers = Customer.query.all()

        return jsonify([customer.to_dict() for customer in customers]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        required_fields = ['customer_name', 'customer_type', 'company_name', 'customer_email', 'customer_phone', 'currency', 'payment_terms', 'total_amount_owed']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
            
        customer_name = data.get('customer_name')
        customer_type = data.get('customer_type')
        company_name = data.get('company_name')
        kra_pin = data.get('kra_pin')
        customer_email = data.get('customer_email')

        if not re.match(email_regex, customer_email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        customer_phone = data.get('customer_phone')
        currency = data.get('currency')
        payment_terms = data.get('payment_terms')
        total_amount_owed = data.get('total_amount_owed')
        amount_paid = data.get('amount_paid')
        

        new_customer = Customer(
            customer_name = customer_name,
            customer_type = customer_type,
            company_name = company_name,
            customer_email = customer_email,
            customer_phone = customer_phone,
            currency = currency,
            kra_pin=kra_pin,
            payment_terms = payment_terms,
            total_amount_owed = total_amount_owed,
            amount_paid=amount_paid,
        )
        try:
            db.session.add(new_customer)
            db.session.commit()
            return jsonify(new_customer.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Customer: {str(e)}'}), 500
        
@app.route('/vendors', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_vendors():
    if request.method == "GET":
        vendor_name = request.args.get('vendor_name')

        if vendor_name:
            # Perform search by name
            vendors = Vendor.query.filter(Vendor.vendor_name.ilike(f'%{vendor_name}%')).all()
        else:
            # If no search term provided, return all items
            vendors = Vendor.query.all()

        return jsonify([vendor.to_dict() for vendor in vendors]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for Vendor'}), 400
        
        required_fields = ['vendor_name', 'vendor_email', 'vendor_phone', 'opening_balance', 'total_amount_owed']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
            
        vendor_name = data.get('vendor_name')
        vendor_phone = data.get('vendor_phone')
        opening_balance = data.get('opening_balance')
        kra_pin = data.get('kra_pin')
        vendor_email = data.get('vendor_email')
        amount_paid = data.get('amount_paid')
        currency = data.get('currency')

        total_amount_owed = data.get('total_amount_owed')

        new_vendor = Vendor(
            vendor_email=vendor_email,
            currency=currency,
            vendor_name=vendor_name,
            vendor_phone=vendor_phone,
            opening_balance = opening_balance,
            kra_pin = kra_pin,
            amount_paid=amount_paid,
            total_amount_owed = total_amount_owed,
        )
        try:
            db.session.add(new_vendor)
            db.session.commit()
            return jsonify(new_vendor.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Vendor: {str(e)}'}), 500
        

@app.route('/deliverynotes', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_deliverynotes():
    if request.method == 'GET':
        # Fetch all quotes from the database
        deliverynotes = DeliveryNote.query.all()
        return jsonify([deliverynote.to_dict() for deliverynote in deliverynotes]), 200

    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Extract and validate general invoice data
        required_fields = ['customer_name', 'delivery_number', 'customer_phone', 'customer_email', 'delivery_date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Extract customer and account information
        customer_name = data.get('customer_name')
        truck_number = data.get('truck_number')
        customer_phone = data.get('customer_phone')
        customer_email = data.get('customer_email')
        invoice_number = data.get('invoice_number')
        delivery_number = data.get('delivery_number')
        vendor_pin = data.get('vendor_pin')
        origin_place = data.get('origin_place')
        destination = data.get('destination')
        driver_contact = data.get('driver_contact')
        driver = data.get('driver')

        # Convert date string to Python date object
        try:
            date_str = data.get('delivery_date')
            delivery_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Expected YYYY-MM-DD'}), 400

        # Validate the customer
        customer = Customer.query.filter_by(customer_name=customer_name).first()
        if not customer:
            return jsonify({'error': f'Customer with name {customer_name} does not exist'}), 400

        # Create the new quote
        new_delieverynote = DeliveryNote(
            customer_name = customer_name,
            truck_number = truck_number,
            customer_phone = customer_phone,
            customer_email = customer_email,
            invoice_number = invoice_number,
            delivery_number = delivery_number,
            delivery_date = delivery_date,
            vendor_pin = vendor_pin,
            origin_place = origin_place,
            destination = destination,
            driver_contact = driver_contact,
            driver = driver,
        )

        # Handle items
        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the quote'}), 400

        for item_data in items_data:
            required_item_fields = ['cargo_description', 'quantity', 'weight']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            # Extract item details
            new_item = DeliveryNoteItem(
                container_number = item_data.get('container_number'),
                cargo_description = item_data.get('cargo_description'),
                quantity = item_data.get('quantity'),
                weight = item_data.get('weight'),
                measurement = item_data.get('measurement'),
            )
            new_delieverynote.items.append(new_item)

        # Add and commit the new quote
        try:
            db.session.add(new_delieverynote)
            db.session.commit()
            return jsonify(new_delieverynote.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Delivery Note: {str(e)}'}), 500
        
@app.route('/deliverynotes/<int:delivery_number>', methods=['GET', 'PATCH'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_patch_deliverynotes_by_delivery_number(delivery_number):
    # Handle the GET request to fetch the quote by quote_number
    if request.method == 'GET':
        delivery_note = DeliveryNote.query.filter_by(delivery_number=delivery_number).first()

        # If quote is not found, return 404
        if not delivery_note:
            return jsonify({'error': 'Delivery Note not found'}), 404

        # Convert the quote object to a dictionary and return it
        return jsonify(delivery_note.to_dict()), 200
        

@app.route('/quotes', methods=['GET', 'POST'])
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_quotes():
    if request.method == 'GET':
        # Fetch all quotes from the database
        quotes = Quote.query.all()
        return jsonify([quote.to_dict() for quote in quotes]), 200

    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Extract and validate general invoice data
        required_fields = ['customer_name', 'quote_number', 'customer_phone', 'customer_email', 'quote_date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Extract customer and account information
        customer_name = data.get('customer_name')
        quote_number = data.get('quote_number')
        customer_email = data.get('customer_email')
        vendor_pin = data.get('vendor_pin')
        type_vat = data.get('type_vat')
        customer_phone = data.get('customer_phone')

        # Convert date string to Python date object
        try:
            date_str = data.get('quote_date')
            quote_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Expected YYYY-MM-DD'}), 400

        # Validate the customer
        customer = Customer.query.filter_by(customer_name=customer_name).first()
        if not customer:
            return jsonify({'error': f'Customer with name {customer_name} does not exist'}), 400

        # Create the new quote
        new_quote = Quote(
            customer_name=customer_name,
            customer_id = customer.id,
            quote_number=quote_number,
            customer_email=customer_email,
            vendor_pin=vendor_pin,
            type_vat=type_vat,
            customer_phone=customer_phone,
            quote_date=quote_date
        )

        # Handle items
        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the quote'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'vat', 'rate_vat', 'rate', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            # Extract item details
            new_item = QuoteItem(
                item_details=item_data.get('item_details'),
                quantity=item_data.get('quantity'),
                description=item_data.get('description'),
                rate=item_data.get('rate'),
                sub_total=item_data.get('sub_total'),
                vat=item_data.get('vat'),
                rate_vat=item_data.get('rate_vat'),
                amount=item_data.get('amount')
            )
            new_quote.items.append(new_item)

        # Add and commit the new quote
        try:
            db.session.add(new_quote)
            db.session.commit()
            return jsonify(new_quote.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Quote: {str(e)}'}), 500
        
@app.route('/quotes/<int:quote_number>', methods=['GET', 'PATCH'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_patch_quotes(quote_number):
    # Handle the GET request to fetch the quote by quote_number
    if request.method == 'GET':
        quote = Quote.query.filter_by(quote_number=quote_number).first()

        # If quote is not found, return 404
        if not quote:
            return jsonify({'error': 'Quote not found'}), 404

        # Convert the quote object to a dictionary and return it
        return jsonify(quote.to_dict()), 200
    

    # Placeholder for PATCH request handling
    # You might need to add code here for handling PATCH requests if required

        
# @app.route('/invoices', methods=['GET', 'POST'])
# @jwt_required()
# @cross_origin(supports_credentials=True, origins=["https://staffmaingibooks.netlify.app", "https://adminmaingibook.netlify.app"])
# def get_and_post_invoiceItem():
#     if request.method == "GET":
#         # Get query parameters
#         customer_name = request.args.get('customer_name')
#         status_filter = request.args.get('status')

#         # Start query
#         query = NewInvoiceItem.query

#         # Filter by customer_name if provided
#         if customer_name:
#             query = query.filter(NewInvoiceItem.customer_name == customer_name)

#         # Filter by status if provided
#         if status_filter:
#             # Convert the comma-separated string into a list
#             status_list = status_filter.split(',')
#             query = query.filter(NewInvoiceItem.status.in_(status_list))

#         # Execute the query and return results
#         invoiceItems = query.all()
#         return jsonify([invoiceItem.to_dict() for invoiceItem in invoiceItems]), 200

@app.route('/invoicetransport', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_invoice_transport():
    if request.method == 'GET':
        customer_name = request.args.get('customer_name')
        status = request.args.get('status')

        query = db.session.query(NewInvoice)

        if customer_name:
            query = query.filter(NewInvoice.customer_name.ilike(f'%{customer_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewInvoice.status.in_(status_list))

        invoices = query.all()
        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['customer_name', 'invoice_number', 'customer_phone', 'customer_email', 'invoice_date', 'invoice_terms', 'due_date', 'sales_person']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Extracting data fields
        customer_name = data.get('customer_name')
        customer_email = data.get('customer_email')
        customer_phone = data.get('customer_phone')
        invoice_number = data.get('invoice_number')
        order_number = data.get('order_number')
        invoice_terms = data.get('invoice_terms')
        due_date = data.get('due_date')
        sales_person = data.get('sales_person')
        currency = data.get('currency')
        status = data.get('status')
        type_vat = data.get('type_vat')
        vendor_pin = data.get('vendor_pin')
        category_name = data.get('category_name')
        amount_paid = data.get('amount_paid')
        amount_owed = data.get('amount_owed')
        consignee = data.get('consignee')

        # Convert date string to Python date object
        date_str = data.get('invoice_date')
        invoice_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        # Check if the customer exists
        customer = Customer.query.filter_by(customer_name=customer_name).first()
        if not customer:
            return jsonify({'error': f'Customer with name {customer_name} does not exist'}), 400

        # Check if the account exists
        account = AccountCategory.query.filter_by(category_name=category_name).first()
        if not account:
            return jsonify({'error': f'Account category with name {category_name} does not exist'}), 400
        

        # Create the new invoice
        new_invoice = NewInvoice(
            customer_id=customer.id,
            category_id=account.id,
            customer_name=customer_name,
            customer_email=customer_email,
            currency=currency,
            customer_phone=customer_phone,
            invoice_number=invoice_number,
            category_name=category_name,
            vendor_pin=vendor_pin,
            order_number=order_number,
            invoice_date=invoice_date,
            invoice_terms=invoice_terms,
            due_date=due_date,
            type_vat=type_vat,
            sales_person=sales_person,
            status=status,
            amount_paid=amount_paid,
            amount_owed=amount_owed,
            consignee=consignee,
        )

        # Handle the items
        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the invoice'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'vat', 'rate_vat', 'rate', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            rate = item_data.get('rate')
            amount = item_data.get('amount')
            vat = item_data.get('vat')
            sub_total = item_data.get('sub_total')
            rate_vat = item_data.get('rate_vat')
            description = item_data.get('description')

            # Fetch Truck object
            truck = Truck.query.filter_by(truck_number=item_details).first()
            if not truck:
                return jsonify({'error': f'Truck with number {item_details} does not exist'}), 400

            # Create a new invoice item
            new_item = NewInvoiceItem(
                item_details=item_details,
                truck_id=truck.id,
                quantity=quantity,
                description=description,
                rate=rate,
                sub_total=sub_total,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount
            )

            # Append the item to the invoice
            new_invoice.items.append(new_item)

            if status == 'UNPAID':
                customer.total_amount_owed += amount

            # Update or Create Total Entry
            total = Total.query.filter_by(account_name=item_details).first()
            if not total:
                new_total = Total(
                    account_name=item_details,
                    amount=amount
                )
                db.session.add(new_total)
            else:
                total.amount += amount

            # Update Debtors
            debtor_account = AccountCategory.query.filter_by(category_name='Debtors').first()
            if debtor_account:
                debtor_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=debtor_account.account_type_id,
                    category_name='Debtors',
                    amount=amount,
                    type_name=debtor_account.type_name,
                    date=invoice_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Debtors Account category does not exist'}), 400

            # Update Sales Account
            sales_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if sales_account:
                sales_account.amount += amount
                new_profit_loss_sales = TradingProfitLossAccount(
                    account_type_id=sales_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=sales_account.type_name,
                    date=invoice_date,
                )
                db.session.add(new_profit_loss_sales)
            else:
                return jsonify({'error': f'Account category {category_name} does not exist'}), 400

        try:
            db.session.add(new_invoice)
            db.session.commit()
            return jsonify(new_invoice.to_dict()), 201
        except Exception as e:
            print("Exception:", str(e))  # Debugging line
            db.session.rollback()
            return jsonify({'error': f'Failed to create Transport Invoice: {str(e)}'}), 500

        
@app.route('/inventoryinvoices', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_inventory_invoice():
    if request.method == 'GET':
        customer_name = request.args.get('customer_name')
        status = request.args.get('status')

        query = db.session.query(NewInvoice)

        if customer_name:
            query = query.filter(NewInvoice.customer_name.ilike(f'%{customer_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewInvoice.status.in_(status_list))

        invoices = query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200

    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['customer_name', 'invoice_number', 'customer_phone', 'customer_email', 'invoice_date', 'invoice_terms', 'due_date', 'sales_person']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Extract invoice fields
        customer_name = data.get('customer_name')
        customer_email = data.get('customer_email')
        customer_phone = data.get('customer_phone')
        invoice_number = data.get('invoice_number')
        order_number = data.get('order_number')
        invoice_terms = data.get('invoice_terms')
        due_date = data.get('due_date')
        sales_person = data.get('sales_person')
        currency = data.get('currency')
        status = data.get('status')
        amount_paid = data.get('amount_paid')
        amount_owed = data.get('amount_owed')
        type_vat = data.get('type_vat')
        vendor_pin = data.get('vendor_pin')
        category_name = data.get('category_name')

        # Convert date string to Python date object
        try:
            date_str = data.get('invoice_date')
            invoice_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

        # Validate customer and account category
        customer = Customer.query.filter_by(customer_name=customer_name).first()
        if not customer:
            return jsonify({'error': f'Customer with name {customer_name} does not exist'}), 400

        account = AccountCategory.query.filter_by(category_name=category_name).first()
        if not account:
            return jsonify({'error': f'Account category {category_name} does not exist'}), 400
        
        # Create the new invoice
        new_invoice = NewInvoice(
            customer_id=customer.id,
            category_id=account.id,
            customer_name=customer_name,
            customer_email=customer_email,
            currency=currency,
            customer_phone=customer_phone,
            invoice_number=invoice_number,
            category_name=category_name,
            vendor_pin=vendor_pin,
            order_number=order_number,
            invoice_date=invoice_date,
            invoice_terms=invoice_terms,
            due_date=due_date,
            type_vat=type_vat,
            sales_person=sales_person,
            status=status,
            amount_paid=amount_paid,
            amount_owed=amount_owed,
        )

        # Handle the items
        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the invoice'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'vat', 'rate_vat', 'rate', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            rate = item_data.get('rate')
            amount = item_data.get('amount')
            vat = item_data.get('vat')
            sub_total = item_data.get('sub_total')
            rate_vat = item_data.get('rate_vat')
            description = item_data.get('description')
            store=item_data.get('store')

            # Create a new invoice item
            new_item = NewInvoiceItem(
                item_details=item_details,
                quantity=quantity,
                description=description,
                rate=rate,
                sub_total=sub_total,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount,
            )

            # Append the item to the invoice
            new_invoice.items.append(new_item)

            customer.total_amount_owed += amount

            # Manage total and stock
            total = Total.query.filter_by(account_name=item_details).first()
            if not total:
                new_total = Total(
                    account_name=item_details,
                    amount=amount
                )
                db.session.add(new_total)
            else:
                total.amount += amount

            print(f"Item Details: {item_details}, Store: {store}")

            stock = StockItem.query.filter_by(item_details=item_details, store=store).first()
            if not stock:
                return jsonify({'error': f'Stock item {item_details} does not exist'}), 400

            stock.quantity -= float(quantity)

            # Update Stock and COGS
            stock_account = AccountCategory.query.filter_by(category_name='Stock').first()
            if stock_account:
                reduce_amount = stock.price * float(quantity)
                new_balancesheet = BalanceSheet(
                    account_type_id=stock_account.account_type_id,
                    category_name='Stock',
                    amount=-reduce_amount,
                    type_name=stock_account.type_name,
                    date=invoice_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Stock Account category does not exist'}), 400

            cogs_account = AccountCategory.query.filter_by(category_name='Cost of Goods Sold').first()
            if cogs_account:
                cogs_amount = stock.price * float(quantity)
                cogs_account.amount += cogs_amount

                new_profit_loss_cogs = TradingProfitLossAccount(
                    account_type_id=cogs_account.account_type_id,
                    category_name='Cost of Goods Sold',
                    amount=cogs_amount,
                    type_name=cogs_account.type_name,
                    date=invoice_date,
                )
                db.session.add(new_profit_loss_cogs)
            else:
                return jsonify({'error': 'COGS Account category does not exist'}), 400

            # Update Sales Account
            new_profit_loss_sales = TradingProfitLossAccount(
                account_type_id=account.account_type_id,
                category_name=category_name,
                amount=amount,
                type_name=account.type_name,
                date=invoice_date,
            )
            db.session.add(new_profit_loss_sales)

            # Update Debtors
            new_balancesheet = BalanceSheet(
                account_type_id=2,
                category_name='Debtors',
                amount=amount,
                type_name='Current Assets',
                date=invoice_date,
            )
            db.session.add(new_balancesheet)

        try:
            db.session.add(new_invoice)
            db.session.commit()
            return jsonify(new_invoice.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Invoice: {str(e)}'}), 500

        
@app.route('/custominvoices', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_custom_invoice():
    if request.method == 'GET':
        customer_name = request.args.get('customer_name')
        status = request.args.get('status')

        query = db.session.query(NewInvoice)

        if customer_name:
            query = query.filter(NewInvoice.customer_name.ilike(f'%{customer_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewInvoice.status.in_(status_list))

        invoices = query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    
    elif request.method == "POST":
        data = request.json
        
        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
            
        required_fields = ['customer_name', 'invoice_number', 'customer_phone', 'customer_email', 'invoice_date', 'invoice_terms', 'due_date', 'sales_person']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

            customer_name = data.get('customer_name')
            customer_email = data.get('customer_email')
            customer_phone = data.get('customer_phone')
            invoice_number = data.get('invoice_number')
            order_number = data.get('order_number')
            invoice_terms = data.get('invoice_terms')
            due_date = data.get('due_date')
            sales_person = data.get('sales_person')
            currency = data.get('currency')
            status=data.get('status')
            type_vat=data.get('type_vat')
            vendor_pin = data.get('vendor_pin')
            category_name = data.get('category_name')
            amount_paid=data.get('amount_paid')
            amount_owed=data.get('amount_owed')
            
            # Convert date string to Python date object
            date_str = data.get('invoice_date')
            invoice_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            
            customer = Customer.query.filter_by(customer_name=customer_name).first()
            if not customer:
                return jsonify({'error': f'Customer with name {customer_name} does not exist'}), 400
            
            account = AccountCategory.query.filter_by(category_name=category_name).first()
            if not account:
                return jsonify({'error': f'Customer with name {customer_name} does not exist'}), 400

            # Create the new invoice
            new_invoice = NewInvoice(
                customer_id=customer.id,
                category_id=account.id,
                customer_name=customer_name,
                customer_email=customer_email,
                currency=currency,
                customer_phone=customer_phone,
                invoice_number=invoice_number,
                category_name=category_name,
                vendor_pin=vendor_pin,
                order_number=order_number,
                invoice_date=invoice_date,
                invoice_terms=invoice_terms,
                due_date=due_date,
                type_vat=type_vat,
                sales_person=sales_person,
                status=status,
                amount_paid=amount_paid,
                amount_owed=amount_owed,
            )

            # Handle the items
        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the invoice'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'vat', 'rate_vat','rate', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400
            
            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            rate = item_data.get('rate')
            amount = item_data.get('amount')
            vat = item_data.get('vat')
            sub_total =  item_data.get('sub_total')
            rate_vat = item_data.get('rate_vat')
            description = item_data.get('description')

            # Create a new invoice item
            new_item = NewInvoiceItem(
                item_details=item_details,
                quantity=quantity,
                description=description,
                rate=rate,
                sub_total=sub_total,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount
            )

            # Append the item to the invoice
            new_invoice.items.append(new_item)

            if status == 'UNPAID':
                customer = Customer.query.filter_by(customer_name=customer_name).first()
                if customer:
                    customer.total_amount_owed += amount
                else:
                    return jsonify({'error': f'Customer Does Not Exist'}), 400

             # **Highlighted Section**
            total = Total.query.filter_by(account_name=item_details).first()
            if not total:
                # Create new Total entry if account_name does not exist
                new_total = Total(
                    account_name=item_details,
                    amount=amount
                )
                db.session.add(new_total)
            else:
                # Update existing Total entry
                total.amount += amount
            
            # Update Debtors
            debtor_account = AccountCategory.query.filter_by(category_name='Debtors').first()
            if debtor_account:
                debtor_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id = debtor_account.account_type_id,
                    category_name='Debtors',
                    amount = amount,
                    type_name=debtor_account.type_name,
                    date = invoice_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Debtors Account category does not exist'}), 400
            
            # Update Sales Account
            sales_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if sales_account:
                sales_account.amount += amount
                new_profit_loss_sales = TradingProfitLossAccount(
                    account_type_id=sales_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=sales_account.type_name,
                    date=invoice_date,
                )
                db.session.add(new_profit_loss_sales)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400

        try:
            db.session.add(new_invoice)
            db.session.commit()
            return jsonify(new_invoice.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Invoice: {str(e)}'}), 500
        
@app.route('/fuelinvoices', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_fuel_invoice():
    if request.method == 'GET':
        customer_name = request.args.get('customer_name')
        status = request.args.get('status')

        query = db.session.query(NewInvoice)

        if customer_name:
            query = query.filter(NewInvoice.customer_name.ilike(f'%{customer_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewInvoice.status.in_(status_list))

        invoices = query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    
    elif request.method == "POST":
        data = request.json
        
        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
            
        required_fields = ['customer_name', 'invoice_number', 'customer_phone', 'customer_email', 'invoice_date', 'invoice_terms', 'due_date', 'sales_person']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

            customer_name = data.get('customer_name')
            customer_email = data.get('customer_email')
            customer_phone = data.get('customer_phone')
            invoice_number = data.get('invoice_number')
            order_number = data.get('order_number')
            invoice_terms = data.get('invoice_terms')
            due_date = data.get('due_date')
            sales_person = data.get('sales_person')
            currency = data.get('currency')
            status=data.get('status')
            type_vat=data.get('type_vat')
            vendor_pin = data.get('vendor_pin')
            category_name = data.get('category_name')
            amount_paid=data.get('amount_paid')
            amount_owed=data.get('amount_owed')
            fuel = data.get('fuel')
            
            # Convert date string to Python date object
            date_str = data.get('invoice_date')
            invoice_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            
            customer = Customer.query.filter_by(customer_name=customer_name).first()
            if not customer:
                return jsonify({'error': f'Customer with name {customer_name} does not exist'}), 400
            
            account = AccountCategory.query.filter_by(category_name=category_name).first()
            if not account:
                return jsonify({'error': f'Customer with name {customer_name} does not exist'}), 400
            
            # Create the new invoice
            new_invoice = NewInvoice(
                customer_id=customer.id,
                category_id=account.id,
                customer_name=customer_name,
                customer_email=customer_email,
                currency=currency,
                customer_phone=customer_phone,
                invoice_number=invoice_number,
                category_name=category_name,
                fuel=fuel,
                vendor_pin=vendor_pin,
                order_number=order_number,
                invoice_date=invoice_date,
                invoice_terms=invoice_terms,
                due_date=due_date,
                type_vat=type_vat,
                sales_person=sales_person,
                status=status,
                amount_paid=amount_paid,
                amount_owed=amount_owed,
            )

            # Handle the items
        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the invoice'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'vat', 'rate_vat','rate', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400
            
            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            rate = item_data.get('rate')
            amount = item_data.get('amount')
            vat = item_data.get('vat')
            sub_total =  item_data.get('sub_total')
            rate_vat = item_data.get('rate_vat')
            description = item_data.get('description')

            # Create a new invoice item
            new_item = NewInvoiceItem(
                item_details=item_details,
                quantity=quantity,
                description=description,
                rate=rate,
                sub_total=sub_total,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount
            )

            # Append the item to the invoice
            new_invoice.items.append(new_item)

             # **Highlighted Section**
            total = Total.query.filter_by(account_name=item_details).first()
            if not total:
                # Create new Total entry if account_name does not exist
                new_total = Total(
                    account_name=item_details,
                    amount=amount
                )
                db.session.add(new_total)
            else:
                # Update existing Total entry
                total.amount += amount
            
            # Update Sales Account
            sales_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if sales_account:
                sales_account.amount += amount
                new_profit_loss_sales = TradingProfitLossAccount(
                    account_type_id=sales_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=sales_account.type_name,
                    date=invoice_date,
                )
                db.session.add(new_profit_loss_sales)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400

        try:
            db.session.add(new_invoice)
            db.session.commit()
            return jsonify(new_invoice.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Failed to create invoice: {str(e)}")
            return jsonify({'error': f'Failed to create Invoice: {str(e)}'}), 500
        
@app.route('/invoicepayment', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_invoicepayments():
    if request.method == 'GET':
        customer_name = request.args.get('customer_name')
        status = request.args.get('status')

        query = db.session.query(NewInvoice)

        if customer_name:
            query = query.filter(NewInvoice.customer_name.ilike(f'%{customer_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewInvoice.status.in_(status_list))

        invoices = query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200

@app.route('/invoices', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_invoice():
    if request.method == 'GET':
        
        invoices = NewInvoice.query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200
        
@app.route('/invoices/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_invoices_by_invoice_number(id):
        
        invoice = NewInvoice.query.filter_by(id=id).first()
        
        if request.method == 'GET':
            if not invoice:
                return jsonify({'error': 'Invoice not found'}), 404
            return jsonify(invoice.to_dict()), 200

        elif request.method == 'PATCH':
            data = request.json

            if not data:
                return jsonify({'error': 'No data provided for update'}), 400
            
            if 'date' in data:
                try:
                    data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
                except ValueError:
                    return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400
            

            required_fields = ['customer_name', 'invoice_number', 'customer_phone', 'customer_email', 'invoice_date', 'invoice_terms', 'due_date', 'sales_person']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400

            customer_name = data.get('customer_name')
            customer_email = data.get('customer_email')
            customer_phone = data.get('customer_phone')
            invoice_number = data.get('invoice_number')
            order_number = data.get('order_number')
            invoice_terms = data.get('invoice_terms')
            due_date = data.get('due_date')
            sales_person = data.get('sales_person')
            currency = data.get('currency')
            status=data.get('status')
            type_vat=data.get('type_vat')
            vendor_pin = data.get('vendor_pin')
            category_name = data.get('category_name')
            amount_paid=data.get('amount_paid')
            amount_owed=data.get('amount_owed')
            previous_category_name = data.get('previous_category_name')
            original_amount = data.get('original_amount')
            invoice_total = data.get('invoice_total')
            customer_amount = data.get('customer_amount')
            type_name = data.get('type_name')
            invoice_id = data.get('invoice_id')

            # Convert date string to Python date object
            date_str = data.get('invoice_date')
            invoice_date = datetime.strptime(date_str, '%Y-%m-%d').date()

            # Handle item details
            items_data = data.get('items')
            if not items_data:
                return jsonify({'error': 'No items provided for the invoice'}), 400

            # Clear existing items to avoid duplicates
            invoice.items.clear()  

            # Loop through each item data and check required fields
            for item_data in items_data:
                required_item_fields = ['item_details', 'quantity', 'rate', 'amount', 'vat', 'sub_total', 'rate_vat', 'description']
                missing_item_fields = [field for field in required_item_fields if field not in item_data]
                if missing_item_fields:
                    return jsonify({'error': f'Missing required fields in item: {", ".join(missing_item_fields)}'}), 400

                # Create a new item instance with the provided data and append it to the invoice items
                new_item = NewInvoiceItem(**item_data)
                invoice.items.append(new_item)  # Append to the invoice's items relationship
                

            customer = Customer.query.filter_by(customer_name=customer_name).first()
            if customer:
                customer.total_amount_owed += float(customer_amount)
            else:
                return jsonify ({'error': f'Customer does not exist'}), 400
            
            # Update Debtors
            debtor_account = AccountCategory.query.filter_by(category_name='Debtors').first()
            if debtor_account:
                debtor_account.amount += float(invoice_total)
                new_balancesheet = BalanceSheet(
                    account_type_id=debtor_account.account_type_id,
                    category_name='Debtors',
                    amount=invoice_total,
                    type_name=debtor_account.type_name,
                    date=invoice_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Debtors Account category does not exist'}), 400

            # Update previous Debtors
            prev_debtor_account = AccountCategory.query.filter_by(category_name='Debtors').first()
            if prev_debtor_account:
                prev_debtor_account.amount -= float(original_amount)
                prev_new_balancesheet = BalanceSheet(
                    account_type_id=prev_debtor_account.account_type_id,
                    category_name='Debtors',
                    amount=-float(original_amount),
                    type_name=prev_debtor_account.type_name,
                    date=invoice_date,
                )
                db.session.add(prev_new_balancesheet)
            else:
                return jsonify({'error': 'Debtors Account category does not exist'}), 400
            
            # Update Category
            account = AccountCategory.query.filter_by(category_name=category_name).first()
            if account:
                account.amount += float(invoice_total)
                new_balancesheets = BalanceSheet(
                    account_type_id=account.account_type_id,
                    category_name=category_name,
                    amount=invoice_total,
                    type_name=account.type_name,
                    date=invoice_date,
                )
                db.session.add(new_balancesheets)
            else:
                return jsonify({'error': 'Account category does not exist'}), 400
            
             # Update Previous Category
            previous_account = AccountCategory.query.filter_by(category_name=previous_category_name).first()
            if previous_account:
                previous_account.amount -= float(original_amount)
                old_balancesheets = BalanceSheet(
                    account_type_id=previous_account.account_type_id,
                    category_name=previous_category_name,
                    amount=-float(original_amount),
                    type_name=previous_account.type_name,
                    date=invoice_date,
                )
                db.session.add(old_balancesheets)
            else:
                return jsonify({'error': 'Account category does not exist'}), 400

            # Update Previous Account
            remove_amount = AccountCategory.query.filter_by(category_name=previous_category_name).first()
            if remove_amount:
                remove_amount.amount -= original_amount
                new_profit = TradingProfitLossAccount(
                    account_type_id=remove_amount.account_type_id,
                    category_name=previous_category_name,
                    amount=-float(original_amount),
                    type_name=remove_amount.type_name,
                    date=invoice_date,
                )
                db.session.add(new_profit)
            else:
                return jsonify({'error': f'Account category {category_name} does not exist'}), 400
            
            # Update Sales Account
            sales_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if sales_account:
                sales_account.amount += invoice_total
                new_profit_loss_sales = TradingProfitLossAccount(
                    account_type_id=sales_account.account_type_id,
                    category_name=category_name,
                    amount=invoice_total,
                    type_name=sales_account.type_name,
                    date=invoice_date,
                )
                db.session.add(new_profit_loss_sales)
            else:
                return jsonify({'error': f'Account category {category_name} does not exist'}), 400
            
            # If 'category_name' is provided, update category_id based on category_name
            category_name = data.get('category_name')
            if category_name:
                category = AccountCategory.query.filter_by(category_name=category_name).first()
                if category:
                    invoice.category_id = category.id  # Update the category_id using the category's ID
                else:
                    return jsonify({'error': 'Category not found'}), 400

            # Repeat the same logic for customer_id if necessary
            customer_name = data.get('customer_name')
            if customer_name:
                customer = Customer.query.filter_by(customer_name=customer_name).first()
                if customer:
                    invoice.customer_id = customer.id
                else:
                    return jsonify({'error': 'Customer not found'}), 400
            
            # Update other fields in invoice from data payload
            for key, value in data.items():
                if key not in ['category_id', 'customer_id','items']:
                    setattr(invoice, key, value)

            try:
                db.session.commit()
                return jsonify(invoice.to_dict()), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to update Invoice: {str(e)}'}), 500

        elif request.method == 'DELETE':
            if not invoice:
                return jsonify({'error': 'Invoice not found'}), 404

            try:
                db.session.delete(invoice)
                db.session.commit()
                return jsonify({'message': 'Invoice deleted successfully'}), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to delete Invoice: {str(e)}'}), 500   

@app.route('/invoicepayments/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_invoices_by_id(id):
        
        invoice = NewInvoice.query.filter_by(id=id).first()
        
        if request.method == 'GET':
            if not invoice:
                return jsonify({'error': 'Invoice not found'}), 404
            return jsonify(invoice.to_dict()), 200

        elif request.method == 'PATCH':
            data = request.json

            if not data:
                return jsonify({'error': 'No data provided for update'}), 400

            if not invoice:
                return jsonify({'error': 'Invoice not found'}), 404
            
            if 'date' in data:
                try:
                    data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
                except ValueError:
                    return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

            for key, value in data.items():
                setattr(invoice, key, value)

            try:
                db.session.commit()
                return jsonify(invoice.to_dict()), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to update Invoice: {str(e)}'}), 500

        elif request.method == 'DELETE':
            if not invoice:
                return jsonify({'error': 'Invoice not found'}), 404

            try:
                db.session.delete(invoice)
                db.session.commit()
                return jsonify({'message': 'Invoice deleted successfully'}), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to delete Invoice: {str(e)}'}), 500   

@app.route('/newbills', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_new_bill():
    if request.method == 'GET':
        
        invoices = NewBill.query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
@app.route('/newbillstatus', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_bill_by_name_status():
    if request.method == 'GET':
        vendor_name = request.args.get('vendor_name')
        
        bills = NewBill.query.filter(
            NewBill.vendor_name.ilike(vendor_name),
            NewBill.status.in_(["UNPAID", "PARTIALLY PAID"])
        ).order_by(
            case(
                (NewBill.status == "PARTIALLY PAID", 1),
                (NewBill.status == "UNPAID", 2),
                else_=3  # Any other status goes last
            )
        ).all()

        if not bills:
            return jsonify({"message": "No bills found for this vendor"}), 200

        return jsonify([bill.to_dict() for bill in bills]), 200 
    

@app.route('/sparebills', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_spare_bill():
    if request.method == 'GET':
        vendor_name = request.args.get('vendor_name')
        status = request.args.get('status')

        query = db.session.query(NewBill)

        if vendor_name:
            query = query.filter(NewBill.vendor_name.ilike(f'%{vendor_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewBill.status.in_(status_list))

        invoices = query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['vendor_name', 'bill_number', 'status', 'order_number', 'bill_date', 'payment_terms', 'due_date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        vendor_name = data.get('vendor_name')
        bill_number = data.get('bill_number')
        order_number = data.get('order_number')
        category_name = data.get('category_name')
        payment_terms = data.get('payment_terms')
        due_date = data.get('due_date')
        vendor_phone = data.get('vendor_phone')
        vendor_email = data.get('vendor_email')
        status = data.get('status')
        type_vat=data.get('type_vat')
        vendor_pin=data.get('vendor_pin')
        currency = data.get('currency')
        amount_paid=data.get('amount_paid')
        amount_owed=data.get('amount_owed')
        type_name = data.get('type_name')

        date_str = data.get('bill_date')
        bill_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        
        vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
        if not vendor:
            return jsonify({'error': f'vendor with name {vendor_name} does not exist'}), 400
        
        account = AccountCategory.query.filter_by(category_name=category_name).first()
        if not account:
             return jsonify({'error': f'Customer with name {category_name} does not exist'}), 400
        
        new_bill = NewBill(
            vendor_id = vendor.id,
            category_id=account.id,
            category_name=category_name,
            vendor_name=vendor_name,
            vendor_email=vendor_email,
            vendor_phone=vendor_phone,
            bill_number=bill_number,
            order_number=order_number,
            vendor_pin=vendor_pin,
            bill_date=bill_date,
            payment_terms=payment_terms,
            due_date=due_date,
            status=status,
            currency=currency,
            type_vat=type_vat,
            amount_owed=amount_owed,
            amount_paid=amount_paid,
            type_name = account.type_name,
        )

        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the bill'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'rate', 'vat', 'rate_vat', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            rate = item_data.get('rate')
            vat = item_data.get('vat')
            rate_vat = item_data.get('rate_vat')
            amount = item_data.get('amount')
            sub_total = item_data.get('sub_total')
            measurement = item_data.get('measurement')
            
            new_item = NewBillItem(
                item_details=item_details,
                quantity=quantity,
                rate=rate,
                sub_total=sub_total,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount,
                measurement=measurement,
            )

            new_bill.items.append(new_item)

            spare = SpareSubCategory.query.filter_by(spare_subcategory_name=item_details).first()
            if not spare:
                # Create new Total entry if account_name does not exist
                new_spare_category = SpareSubCategory(
                    spare_subcategory_name = item_details,
                    quantity=quantity,
                    price=rate,
                    measurement=measurement,
                    date=bill_date,
                )
                db.session.add(new_spare_category)
            else:
                # Update existing Total entry
                spare.quantity += float(quantity)

            vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
            if vendor:
                vendor.total_amount_owed += amount
            else:
                return jsonify({'error': f'Customer Does Not Exist'}), 400
            
            # Create or Update an Expense
            expense = Expense.query.filter_by(expense_name=item_details).first()
            if not expense:
                new_expense = Expense(
                    expense_name=item_details,
                    expense_amount=amount,
                )

                db.session.add(new_expense)
            else:
                expense.expense_amount += amount
            
            # Update Creditors
            creditor_account = AccountCategory.query.filter_by(category_name='Creditors').first()
            if creditor_account:
                creditor_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=creditor_account.account_type_id,
                    category_name='Creditors',
                    amount=float(amount),
                    type_name=creditor_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
            
            # Update Purchase Account
            purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if purchases_account:
                purchases_account.amount += amount
                new_profit_loss_sales = TradingProfitLossAccount(
                    account_type_id=purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_profit_loss_sales)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400
            
            # Update Balance Sheet Purchase Account
            balance_sheet_purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if balance_sheet_purchases_account:
                balance_sheet_purchases_account.amount += amount
                new_balancesheet = BalanceSheet(
                    account_type_id=balance_sheet_purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=balance_sheet_purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400

        try:
            db.session.add(new_bill)
            db.session.commit()
            return jsonify(new_bill.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Bill: {str(e)}'}), 500
        
@app.route('/inventorybills', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_inventory_bill():
    if request.method == 'GET':
        vendor_name = request.args.get('vendor_name')
        status = request.args.get('status')

        query = db.session.query(NewBill)

        if vendor_name:
            query = query.filter(NewBill.vendor_name.ilike(f'%{vendor_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewBill.status.in_(status_list))

        invoices = query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['vendor_name', 'bill_number', 'status', 'order_number', 'bill_date', 'payment_terms', 'due_date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        vendor_name = data.get('vendor_name')
        bill_number = data.get('bill_number')
        order_number = data.get('order_number')
        category_name = data.get('category_name')
        payment_terms = data.get('payment_terms')
        due_date = data.get('due_date')
        vendor_phone = data.get('vendor_phone')
        vendor_email = data.get('vendor_email')
        status = data.get('status')
        type_vat=data.get('type_vat')
        vendor_pin=data.get('vendor_pin')
        currency = data.get('currency')
        amount_paid=data.get('amount_paid')
        amount_owed=data.get('amount_owed')

        date_str = data.get('bill_date')
        bill_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        
        vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
        if not vendor:
            return jsonify({'error': f'vendor with name {vendor_name} does not exist'}), 400
        
        account = AccountCategory.query.filter_by(category_name=category_name).first()
        if not account:
             return jsonify({'error': f'Customer with name {category_name} does not exist'}), 400

        new_bill = NewBill(
            vendor_id = vendor.id,
            category_id=account.id,
            category_name=category_name,
            vendor_name=vendor_name,
            vendor_email=vendor_email,
            vendor_phone=vendor_phone,
            bill_number=bill_number,
            order_number=order_number,
            vendor_pin=vendor_pin,
            bill_date=bill_date,
            payment_terms=payment_terms,
            due_date=due_date,
            amount_paid=amount_paid,
            amount_owed=amount_owed,
            status=status,
            currency=currency,
            type_vat=type_vat,
            type_name = account.type_name,
        )

        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the bill'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'rate', 'vat', 'rate_vat', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            unit = item_data.get('unit')
            rate = item_data.get('rate')
            vat = item_data.get('vat')
            rate_vat = item_data.get('rate_vat')
            amount = item_data.get('amount')
            sub_total = item_data.get('sub_total')
            measurement= item_data.get('measurement')
            store = item_data.get('store')
            
            new_item = NewBillItem(
                item_details=item_details,
                measurement=measurement,
                quantity=quantity,
                unit=unit,
                rate=rate,
                sub_total=sub_total,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount,
            )

            new_bill.items.append(new_item)


             # **Highlighted Section**
            stock = StockItem.query.filter_by(item_details=item_details, measurement=measurement, store=store).first()
            if stock:

                # Update existing Total entry
                stock.quantity += float(quantity)
            else:
                # Create new Total entry if account_name does not exist
                new_stock = StockItem(
                    item_details=item_details,
                    quantity= quantity,
                    price=rate,
                    measurement=measurement,
                    store=store
                )
                db.session.add(new_stock)

            vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
            if vendor:
                vendor.total_amount_owed += amount
            else:
                return jsonify({'error': f'Customer Does Not Exist'}), 400
            
            # Create or Update an Expense
            expense = Expense.query.filter_by(expense_name=item_details).first()
            if not expense:
                new_expense = Expense(
                    expense_name=item_details,
                    expense_amount=amount,
                )

                db.session.add(new_expense)
            else:
                expense.expense_amount += amount


            # Update Creditors
            creditor_account = AccountCategory.query.filter_by(category_name='Creditors').first()
            if creditor_account:
                creditor_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=creditor_account.account_type_id,
                    category_name='Creditors',
                    amount=float(amount),
                    type_name=creditor_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
            
            # Update Purchase Account
            purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if purchases_account:
                purchases_account.amount += amount
                new_profit_loss_sales = TradingProfitLossAccount(
                    account_type_id=purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_profit_loss_sales)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400
            
            # Update Balance Sheet Purchase Account
            balance_sheet_purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if balance_sheet_purchases_account:
                balance_sheet_purchases_account.amount += amount
                new_balancesheet = BalanceSheet(
                    account_type_id=balance_sheet_purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=balance_sheet_purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400

        try:
            db.session.add(new_bill)
            db.session.commit()
            return jsonify(new_bill.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Bill: {str(e)}'}), 500
        
@app.route('/custombills', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_custom_bill():
    if request.method == 'GET':
        vendor_name = request.args.get('vendor_name')
        status = request.args.get('status')

        query = db.session.query(NewBill)

        if vendor_name:
            query = query.filter(NewBill.vendor_name.ilike(f'%{vendor_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewBill.status.in_(status_list))

        invoices = query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['vendor_name', 'bill_number', 'status', 'order_number', 'bill_date', 'payment_terms', 'due_date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        vendor_name = data.get('vendor_name')
        bill_number = data.get('bill_number')
        order_number = data.get('order_number')
        category_name = data.get('category_name')
        payment_terms = data.get('payment_terms')
        due_date = data.get('due_date')
        vendor_phone = data.get('vendor_phone')
        vendor_email = data.get('vendor_email')
        status = data.get('status')
        type_vat=data.get('type_vat')
        vendor_pin=data.get('vendor_pin')
        currency = data.get('currency')
        amount_paid=data.get('amount_paid')
        amount_owed=data.get('amount_owed')

        date_str = data.get('bill_date')
        bill_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        
        vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
        if not vendor:
            return jsonify({'error': f'vendor with name {vendor_name} does not exist'}), 400
        
        account = AccountCategory.query.filter_by(category_name=category_name).first()
        if not account:
             return jsonify({'error': f'Customer with name {category_name} does not exist'}), 400

        new_bill = NewBill(
            vendor_id = vendor.id,
            category_id=account.id,
            category_name=category_name,
            vendor_name=vendor_name,
            vendor_email=vendor_email,
            vendor_phone=vendor_phone,
            bill_number=bill_number,
            order_number=order_number,
            vendor_pin=vendor_pin,
            bill_date=bill_date,
            payment_terms=payment_terms,
            due_date=due_date,
            amount_paid=amount_paid,
            amount_owed=amount_owed,
            status=status,
            currency=currency,
            type_vat=type_vat,
            type_name = account.type_name,
        )

        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the bill'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'rate', 'vat', 'rate_vat', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            rate = item_data.get('rate')
            vat = item_data.get('vat')
            rate_vat = item_data.get('rate_vat')
            amount = item_data.get('amount')
            sub_total = item_data.get('sub_total')
            spare_name= item_data.get('spare_name')
            
            new_item = NewBillItem(
                item_details=item_details,
                spare_name=spare_name,
                quantity=quantity,
                rate=rate,
                sub_total=sub_total,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount,
            )

            new_bill.items.append(new_item)

            vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
            if vendor:
                vendor.total_amount_owed += amount
            else:
                return jsonify({'error': f'Customer Does Not Exist'}), 400
            
            # Create or Update an Expense
            expense = Expense.query.filter_by(expense_name=item_details).first()
            if not expense:
                new_expense = Expense(
                    expense_name=item_details,
                    expense_amount=amount,
                )

                db.session.add(new_expense)
            else:
                expense.expense_amount += amount

            
            # Update Creditors
            creditor_account = AccountCategory.query.filter_by(category_name='Creditors').first()
            if creditor_account:
                creditor_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=creditor_account.account_type_id,
                    category_name='Creditors',
                    amount=float(amount),
                    type_name=creditor_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
            
            # Update Purchase Account
            purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if purchases_account:
                purchases_account.amount += amount
                new_profit_loss_sales = TradingProfitLossAccount(
                    account_type_id=purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_profit_loss_sales)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400
            
            # Update Balance Sheet Purchase Account
            balance_sheet_purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if balance_sheet_purchases_account:
                balance_sheet_purchases_account.amount += amount
                new_balancesheet = BalanceSheet(
                    account_type_id=balance_sheet_purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=balance_sheet_purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400

        try:
            db.session.add(new_bill)
            db.session.commit()
            return jsonify(new_bill.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Bill: {str(e)}'}), 500
        
@app.route('/fuelbills', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_fuel_bill():
    if request.method == 'GET':
        vendor_name = request.args.get('vendor_name')
        status = request.args.get('status')

        query = db.session.query(NewBill)

        if vendor_name:
            query = query.filter(NewBill.vendor_name.ilike(f'%{vendor_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewBill.status.in_(status_list))

        invoices = query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['vendor_name', 'bill_number', 'status', 'payment_made', 'order_number', 'bill_date', 'payment_terms', 'due_date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        vendor_name = data.get('vendor_name')
        bill_number = data.get('bill_number')
        order_number = data.get('order_number')
        payment_made = data.get('payment_made')
        category_name = data.get('category_name')
        payment_terms = data.get('payment_terms')
        due_date = data.get('due_date')
        vendor_phone = data.get('vendor_phone')
        vendor_email = data.get('vendor_email')
        status = data.get('status')
        type_vat=data.get('type_vat')
        vendor_pin=data.get('vendor_pin')
        currency = data.get('currency')
        amount_paid=data.get('amount_paid')
        amount_owed=data.get('amount_owed')

        date_str = data.get('bill_date')
        bill_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        
        vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
        if not vendor:
            return jsonify({'error': f'vendor with name {vendor_name} does not exist'}), 400
        
        account = AccountCategory.query.filter_by(category_name=category_name).first()
        if not account:
             return jsonify({'error': f'Customer with name {category_name} does not exist'}), 400

        new_bill = NewBill(
            vendor_id = vendor.id,
            category_id=account.id,
            category_name=category_name,
            vendor_name=vendor_name,
            vendor_email=vendor_email,
            vendor_phone=vendor_phone,
            bill_number=bill_number,
            order_number=order_number,
            vendor_pin=vendor_pin,
            bill_date=bill_date,
            payment_terms=payment_terms,
            due_date=due_date,
            amount_paid=amount_paid,
            amount_owed=amount_owed,
            status=status,
            currency=currency,
            type_vat=type_vat,
            type_name = account.type_name,

        )

        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the bill'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'rate', 'vat', 'rate_vat', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            rate = item_data.get('rate')
            vat = item_data.get('vat')
            rate_vat = item_data.get('rate_vat')
            amount = item_data.get('amount')
            sub_total = item_data.get('sub_total')
            spare_name= item_data.get('spare_name')
            
            new_item = NewBillItem(
                item_details=item_details,
                spare_name=spare_name,
                quantity=quantity,
                rate=rate,
                sub_total=sub_total,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount,
            )

            new_bill.items.append(new_item)

            vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
            if vendor:
                vendor.total_amount_owed += amount
            else:
                return jsonify({'error': f'Customer Does Not Exist'}), 400
            
            # Create or Update an Expense
            expense = Expense.query.filter_by(expense_name=item_details).first()
            if not expense:
                new_expense = Expense(
                    expense_name=item_details,
                    expense_amount=amount,
                )

                db.session.add(new_expense)
            else:
                expense.expense_amount += amount

            
             # **Highlighted Section**
            pump = PumpName.query.filter_by(pump_name=item_details).first()
            if pump:
                
                    latest_reading = PumpName.query.filter_by(pump_name=item_details).first()
                    new_pump_update = PumpUpdate(
                        pump_id=pump.id,
                        pump_name=item_details,
                        litres=float(quantity),
                        reading=latest_reading.reading,
                        date=bill_date,
                    )

                    pump.litres += float(quantity)
                    db.session.add(new_pump_update)
            else:
                    return jsonify({'error': f'Pump with name {item_details} does not exist'}), 400        

            # Update Creditors
            creditor_account = AccountCategory.query.filter_by(category_name='Creditors').first()
            if creditor_account:
                creditor_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=creditor_account.account_type_id,
                    category_name='Creditors',
                    amount=float(amount),
                    type_name=creditor_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
            
            # Update Purchase Account
            purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if purchases_account:
                purchases_account.amount += amount
                new_profit_loss_sales = TradingProfitLossAccount(
                    account_type_id=purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_profit_loss_sales)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400
            
            # Update Balance Sheet Purchase Account
            balance_sheet_purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if balance_sheet_purchases_account:
                balance_sheet_purchases_account.amount += amount
                new_balancesheet = BalanceSheet(
                    account_type_id=balance_sheet_purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=balance_sheet_purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400
                

        try:
            db.session.add(new_bill)
            db.session.commit()
            return jsonify(new_bill.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Bill: {str(e)}'}), 500
        
@app.route('/creditfuelbills', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_credit_fuel_bill():
    if request.method == 'GET':
        vendor_name = request.args.get('vendor_name')
        status = request.args.get('status')

        query = db.session.query(NewBill)

        if vendor_name:
            query = query.filter(NewBill.vendor_name.ilike(f'%{vendor_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewBill.status.in_(status_list))

        invoices = query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['vendor_name', 'bill_number', 'status', 'order_number', 'bill_date', 'payment_terms', 'due_date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        vendor_name = data.get('vendor_name')
        bill_number = data.get('bill_number')
        order_number = data.get('order_number')
        category_name = data.get('category_name')
        payment_terms = data.get('payment_terms')
        due_date = data.get('due_date')
        vendor_phone = data.get('vendor_phone')
        vendor_email = data.get('vendor_email')
        status = data.get('status')
        type_vat=data.get('type_vat')
        vendor_pin=data.get('vendor_pin')
        currency = data.get('currency')
        amount_paid=data.get('amount_paid')
        amount_owed=data.get('amount_owed')

        date_str = data.get('bill_date')
        bill_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        
        vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
        if not vendor:
            return jsonify({'error': f'vendor with name {vendor_name} does not exist'}), 400
        
        account = AccountCategory.query.filter_by(category_name=category_name).first()
        if not account:
             return jsonify({'error': f'Customer with name {category_name} does not exist'}), 400

        new_bill = NewBill(
            vendor_id = vendor.id,
            category_id=account.id,
            category_name=category_name,
            vendor_name=vendor_name,
            vendor_email=vendor_email,
            vendor_phone=vendor_phone,
            bill_number=bill_number,
            order_number=order_number,
            vendor_pin=vendor_pin,
            bill_date=bill_date,
            payment_terms=payment_terms,
            due_date=due_date,
            amount_paid=amount_paid,
            amount_owed=amount_owed,
            status=status,
            currency=currency,
            type_vat=type_vat,
            type_name = account.type_name,
        )

        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the bill'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'rate', 'vat', 'rate_vat', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            rate = item_data.get('rate')
            vat = item_data.get('vat')
            rate_vat = item_data.get('rate_vat')
            amount = item_data.get('amount')
            sub_total = item_data.get('sub_total')
            spare_name= item_data.get('spare_name')

            truck = Truck.query.filter_by(truck_number=item_details).first()
            if not truck:
                return jsonify({'error': f'Truck not available'}), 400
        
            new_item = NewBillItem(
                item_details=item_details,
                truck_id=truck.id,
                spare_name=spare_name,
                quantity=quantity,
                rate=rate,
                sub_total=sub_total,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount,
            )

            new_bill.items.append(new_item)

            vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
            if vendor:
                vendor.total_amount_owed += amount
            else:
                return jsonify({'error': f'Customer Does Not Exist'}), 400
            
            # Create or Update an Expense
            expense = Expense.query.filter_by(expense_name=item_details).first()
            if not expense:
                new_expense = Expense(
                    expense_name=item_details,
                    expense_amount=amount,
                )

                db.session.add(new_expense)
            else:
                expense.expense_amount += amount      

            # Update Creditors
            creditor_account = AccountCategory.query.filter_by(category_name='Creditors').first()
            if creditor_account:
                creditor_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=creditor_account.account_type_id,
                    category_name='Creditors',
                    amount=float(amount),
                    type_name=creditor_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
            
            # Update Purchase Account
            purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if purchases_account:
                purchases_account.amount += amount
                new_profit_loss_sales = TradingProfitLossAccount(
                    account_type_id=purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_profit_loss_sales)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400
            
            # Update Balance Sheet Purchase Account
            balance_sheet_purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if balance_sheet_purchases_account:
                balance_sheet_purchases_account.amount += amount
                new_balancesheet = BalanceSheet(
                    account_type_id=balance_sheet_purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=balance_sheet_purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400
                

        try:
            db.session.add(new_bill)
            db.session.commit()
            return jsonify(new_bill.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Bill: {str(e)}'}), 500
        
@app.route('/tyrebills', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_tyre_bill():
    if request.method == 'GET':
        vendor_name = request.args.get('vendor_name')
        status = request.args.get('status')

        query = db.session.query(NewBill)

        if vendor_name:
            query = query.filter(NewBill.vendor_name.ilike(f'%{vendor_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewBill.status.in_(status_list))

        invoices = query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['vendor_name', 'bill_number', 'status','order_number', 'bill_date', 'payment_terms', 'due_date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        vendor_name = data.get('vendor_name')
        bill_number = data.get('bill_number')
        order_number = data.get('order_number')
        category_name = data.get('category_name')
        payment_terms = data.get('payment_terms')
        due_date = data.get('due_date')
        vendor_phone = data.get('vendor_phone')
        vendor_email = data.get('vendor_email')
        status = data.get('status')
        type_vat=data.get('type_vat')
        vendor_pin=data.get('vendor_pin')
        currency = data.get('currency')
        amount_paid=data.get('amount_paid')
        amount_owed=data.get('amount_owed')
        

        date_str = data.get('bill_date')
        bill_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        
        vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
        if not vendor:
            return jsonify({'error': f'vendor with name {vendor_name} does not exist'}), 400
        
        account = AccountCategory.query.filter_by(category_name=category_name).first()
        if not account:
             return jsonify({'error': f'Customer with name {category_name} does not exist'}), 400

        new_bill = NewBill(
            vendor_id = vendor.id,
            category_id=account.id,
            category_name=category_name,
            vendor_name=vendor_name,
            vendor_email=vendor_email,
            vendor_phone=vendor_phone,
            bill_number=bill_number,
            order_number=order_number,
            vendor_pin=vendor_pin,
            bill_date=bill_date,
            payment_terms=payment_terms,
            due_date=due_date,
            amount_paid=amount_paid,
            amount_owed=amount_owed,
            status=status,
            currency=currency,
            type_vat=type_vat,
            type_name = account.type_name,

        )

        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the bill'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'rate', 'vat', 'rate_vat', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            rate = item_data.get('rate')
            vat = item_data.get('vat')
            rate_vat = item_data.get('rate_vat')
            amount = item_data.get('amount')
            sub_total = item_data.get('sub_total')
            description= item_data.get('description')
            
            new_item = NewBillItem(
                item_details=item_details,
                description=description,
                quantity=quantity,
                rate=rate,
                sub_total=sub_total,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount,
            )

            new_bill.items.append(new_item)

            vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
            if vendor:
                vendor.total_amount_owed += amount
            else:
                return jsonify({'error': f'Customer Does Not Exist'}), 400
            
            # Create or Update an Expense
            expense = Expense.query.filter_by(expense_name=item_details).first()
            if not expense:
                new_expense = Expense(
                    expense_name=item_details,
                    expense_amount=amount,
                )

                db.session.add(new_expense)
            else:
                expense.expense_amount += amount

            
             # **Highlighted Section**
            tyre = Tyre.query.filter_by(size=description, item_details=item_details).first()
            if not tyre:
                # Create a new Tyre object and add it to the session
                new_tyre = Tyre(
                    item_details=item_details,
                    quantity=float(quantity),
                    size=description,
                    price=rate,
                )
                db.session.add(new_tyre)
            else:
                # Update the quantity of the existing Tyre object
                tyre.quantity += float(quantity)
                tyre.price = rate
                
            # Update Creditors
            creditor_account = AccountCategory.query.filter_by(category_name='Creditors').first()
            if creditor_account:
                creditor_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=creditor_account.account_type_id,
                    category_name='Creditors',
                    amount=float(amount),
                    type_name=creditor_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
            
            # Update Purchase Account
            purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if purchases_account:
                purchases_account.amount += amount
                new_profit_loss_sales = TradingProfitLossAccount(
                    account_type_id=purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_profit_loss_sales)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400
            
            # Update Balance Sheet Purchase Account
            balance_sheet_purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if balance_sheet_purchases_account:
                balance_sheet_purchases_account.amount += amount
                new_balancesheet = BalanceSheet(
                    account_type_id=balance_sheet_purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=balance_sheet_purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400

        try:
            db.session.add(new_bill)
            db.session.commit()
            return jsonify(new_bill.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Bill: {str(e)}'}), 500
        
@app.route('/retreadtyrebills', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_retread_tyre_bill():
    if request.method == 'GET':
        vendor_name = request.args.get('vendor_name')
        status = request.args.get('status')

        query = db.session.query(NewBill)

        if vendor_name:
            query = query.filter(NewBill.vendor_name.ilike(f'%{vendor_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewBill.status.in_(status_list))

        invoices = query.all()

        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['vendor_name', 'bill_number', 'status', 'order_number', 'bill_date', 'payment_terms', 'due_date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        vendor_name = data.get('vendor_name')
        bill_number = data.get('bill_number')
        order_number = data.get('order_number')
        category_name = data.get('category_name')
        payment_terms = data.get('payment_terms')
        due_date = data.get('due_date')
        vendor_phone = data.get('vendor_phone')
        vendor_email = data.get('vendor_email')
        status = data.get('status')
        type_vat=data.get('type_vat')
        vendor_pin=data.get('vendor_pin')
        currency = data.get('currency')
        amount_paid=data.get('amount_paid')
        amount_owed=data.get('amount_owed')


        date_str = data.get('bill_date')
        bill_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        
        vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
        if not vendor:
            return jsonify({'error': f'vendor with name {vendor_name} does not exist'}), 400
        
        account = AccountCategory.query.filter_by(category_name=category_name).first()
        if not account:
             return jsonify({'error': f'Customer with name {category_name} does not exist'}), 400

        new_bill = NewBill(
            vendor_id = vendor.id,
            category_id=account.id,
            category_name=category_name,
            vendor_name=vendor_name,
            vendor_email=vendor_email,
            vendor_phone=vendor_phone,
            bill_number=bill_number,
            order_number=order_number,
            vendor_pin=vendor_pin,
            bill_date=bill_date,
            payment_terms=payment_terms,
            due_date=due_date,
            amount_paid=amount_paid,
            amount_owed=amount_owed,
            status=status,
            currency=currency,
            type_vat=type_vat,
            type_name = account.type_name,

        )

        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the bill'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'rate', 'vat', 'rate_vat', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            rate = item_data.get('rate')
            vat = item_data.get('vat')
            rate_vat = item_data.get('rate_vat')
            amount = item_data.get('amount')
            sub_total = item_data.get('sub_total')
            description= item_data.get('description')
            spare_name = item_data.get('spare_name')
            tyre_mileage = item_data.get('tyre_mileage')

            
            new_item = NewBillItem(
                item_details=item_details,
                spare_name = spare_name,
                description=description,
                quantity=quantity,
                rate=rate,
                sub_total=sub_total,
                tyre_mileage=tyre_mileage,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount,
            )

            new_bill.items.append(new_item)

            vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
            if vendor:
                vendor.total_amount_owed += amount
            else:
                return jsonify({'error': f'Customer Does Not Exist'}), 400
            
            # Create or Update an Expense
            expense = Expense.query.filter_by(expense_name=item_details).first()
            if not expense:
                new_expense = Expense(
                    expense_name=item_details,
                    expense_amount=amount,
                )

                db.session.add(new_expense)
            else:
                expense.expense_amount += amount
            

            new_usedtyre =OldTyres(
                truck_id = None,
                item_details = description,
                size = spare_name,
                tyre_mileage = tyre_mileage,
                retread_counter = 1,
                date = None,
                truck_number = None,
                serial_number = item_details,
                starting_mileage = 0,
                final_mileage = 0,
                retread_status = 'AVAILABLE',
                position = None,
                reason = None,
                status = 'Store',
                condition = 'Good',
            )
            
            db.session.add(new_usedtyre)

            # tyre = OldTyres.query.filter_by(serial_number=item_details).first()
            # if tyre:
            #         tyre.retread_counter += 1
            #         tyre.condition = 'Good'
            #         tyre.retread_status = 'AVAILABLE'
            # else:
            #     return jsonify({'error': f'Tyre Does Not Exist'}), 400


            # retread_tyre = ShopRetread.query.filter_by(serial_number=item_details, position='SHOP').first()
            # if retread_tyre:
            #     db.session.delete(retread_tyre)


            # Update Creditors
            creditor_account = AccountCategory.query.filter_by(category_name='Creditors').first()
            if creditor_account:
                creditor_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=creditor_account.account_type_id,
                    category_name='Creditors',
                    amount=float(amount),
                    type_name=creditor_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
            
            # Update Purchase Account
            purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if purchases_account:
                purchases_account.amount += amount
                new_profit_loss_sales = TradingProfitLossAccount(
                    account_type_id=purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_profit_loss_sales)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400
            
            # Update Balance Sheet Purchase Account
            balance_sheet_purchases_account = AccountCategory.query.filter_by(category_name=category_name).first()
            if balance_sheet_purchases_account:
                balance_sheet_purchases_account.amount += amount
                new_balancesheet = BalanceSheet(
                    account_type_id=balance_sheet_purchases_account.account_type_id,
                    category_name=category_name,
                    amount=amount,
                    type_name=balance_sheet_purchases_account.type_name,
                    date=bill_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify ({'error': f'Stock item {item_details} does not exist'}), 400
                
        try:
            db.session.add(new_bill)
            db.session.commit()
            return jsonify(new_bill.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Bill: {str(e)}'}), 500
        
@app.route('/newbills/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_bills_by_id(id):
        
        invoice = NewBill.query.filter_by(id=id).first()
        
        if request.method == 'GET':
            if not invoice:
                return jsonify({'error': 'Invoice not found'}), 404
            return jsonify(invoice.to_dict()), 200

        elif request.method == 'PATCH':
            data = request.json

            if not data:
                return jsonify({'error': 'No data provided for update'}), 400
            
            if 'date' in data:
                try:
                    data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
                except ValueError:
                    return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

            required_fields = ['vendor_name', 'bill_number', 'status', 'order_number', 'bill_date', 'payment_terms', 'due_date']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400
            
            vendor_name = data.get('vendor_name')
            bill_number = data.get('bill_number')
            order_number = data.get('order_number')
            category_name = data.get('category_name')
            payment_terms = data.get('payment_terms')
            due_date = data.get('due_date')
            vendor_phone = data.get('vendor_phone')
            vendor_email = data.get('vendor_email')
            status = data.get('status')
            type_vat=data.get('type_vat')
            vendor_pin=data.get('vendor_pin')
            currency = data.get('currency')
            amount_paid=data.get('amount_paid')
            amount_owed=data.get('amount_owed')
            bill_total = data.get('bill_total')
            original_amount = data.get('original_amount')
            vendor_amount = data.get('vendor_amount')
            previous_category_name = data.get('previous_category_name')

            date_str = data.get('bill_date')
            bill_date = datetime.strptime(date_str, '%Y-%m-%d').date()

            items_data = data.get('items')
            if not items_data:
                return jsonify({'error': 'No items provided for the bill'}), 400
            
            # Clear existing items to avoid duplicates
            invoice.items.clear()

            for item_data in items_data:
                required_item_fields = ['item_details', 'quantity', 'rate', 'vat', 'rate_vat', 'amount']
                for field in required_item_fields:
                    if field not in item_data:
                        return jsonify({'error': f'Missing required field in item: {field}'}), 400

                new_item = NewBillItem(**item_data)
                invoice.items.append(new_item)

                vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
                if vendor:
                    vendor.total_amount_owed += float(vendor_amount)
                else:
                    return jsonify ({'error': f'Customer does not exist'}), 400
                
                # Update Creditors
                debtor_account = AccountCategory.query.filter_by(category_name='Creditors').first()
                if debtor_account:
                    debtor_account.amount += float(bill_total)
                    new_balancesheet = BalanceSheet(
                        account_type_id=debtor_account.account_type_id,
                        category_name='Creditors',
                        amount=bill_total,
                        type_name=debtor_account.type_name,
                        date=bill_date,
                    )
                    db.session.add(new_balancesheet)
                else:
                    return jsonify({'error': 'Debtors Account category does not exist'}), 400

                # Update previous Creditors
                prev_debtor_account = AccountCategory.query.filter_by(category_name='Creditors').first()
                if prev_debtor_account:
                    prev_debtor_account.amount -= float(original_amount)
                    prev_new_balancesheet = BalanceSheet(
                        account_type_id=prev_debtor_account.account_type_id,
                        category_name='Creditors',
                        amount=-float(original_amount),
                        type_name=prev_debtor_account.type_name,
                        date=bill_date,
                    )
                    db.session.add(prev_new_balancesheet)
                else:
                    return jsonify({'error': 'Debtors Account category does not exist'}), 400
                
                # Update Category
                account = AccountCategory.query.filter_by(category_name=category_name).first()
                if account:
                    account.amount += float(bill_total)
                    new_balancesheets = BalanceSheet(
                        account_type_id=account.account_type_id,
                        category_name=category_name,
                        amount=bill_total,
                        type_name=account.type_name,
                        date=bill_date,
                    )
                    db.session.add(new_balancesheets)
                else:
                    return jsonify({'error': 'Account category does not exist'}), 400
                
                # Update Previous Category
                previous_account = AccountCategory.query.filter_by(category_name=previous_category_name).first()
                if previous_account:
                    previous_account.amount -= float(original_amount)
                    old_balancesheets = BalanceSheet(
                        account_type_id=previous_account.account_type_id,
                        category_name=previous_category_name,
                        amount=-float(original_amount),
                        type_name=previous_account.type_name,
                        date=bill_date,
                    )
                    db.session.add(old_balancesheets)
                else:
                    return jsonify({'error': 'Account category does not exist'}), 400

                # Update Previous Account
                remove_amount = AccountCategory.query.filter_by(category_name=previous_category_name).first()
                if remove_amount:
                    remove_amount.amount -= original_amount
                    new_profit = TradingProfitLossAccount(
                        account_type_id=remove_amount.account_type_id,
                        category_name=previous_category_name,
                        amount=-float(original_amount),
                        type_name=remove_amount.type_name,
                        date=bill_date,
                    )
                    db.session.add(new_profit)
                else:
                    return jsonify({'error': f'Account category {category_name} does not exist'}), 400
                
                # Update Sales Account
                sales_account = AccountCategory.query.filter_by(category_name=category_name).first()
                if sales_account:
                    sales_account.amount += bill_total
                    new_profit_loss_sales = TradingProfitLossAccount(
                        account_type_id=sales_account.account_type_id,
                        category_name=category_name,
                        amount=bill_total,
                        type_name=sales_account.type_name,
                        date=bill_date,
                    )
                    db.session.add(new_profit_loss_sales)
                else:
                    return jsonify({'error': f'Account category {category_name} does not exist'}), 400
                
                # If 'category_name' is provided, update category_id based on category_name
                category_name = data.get('category_name')
                if category_name:
                    category = AccountCategory.query.filter_by(category_name=category_name).first()
                    if category:
                        invoice.category_id = category.id  # Update the category_id using the category's ID
                    else:
                        return jsonify({'error': 'Category not found'}), 400

                # Repeat the same logic for customer_id if necessary
                vendor_name = data.get('vendor_name')
                if vendor_name:
                    vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
                    if vendor:
                        invoice.customer_id = vendor.id
                    else:
                        return jsonify({'error': 'Vendor not found'}), 400
                
                # Repeat the same logic for customer_id if necessary
                type_name = data.get('type_name')
                if type_name:
                    account = AccountCategory.query.filter_by(category_name=category_name).first()
                    if account:
                        invoice.type_name = account.type_name
                    else:
                        return jsonify({'error': 'Account not found'}), 400
                

                # Update other fields in invoice from data payload
                for key, value in data.items():
                    if key not in ['category_id', 'vendor_id','items', 'type_name']:
                        setattr(invoice, key, value)

            try:
                db.session.commit()
                return jsonify(invoice.to_dict()), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to update Invoice: {str(e)}'}), 500

        elif request.method == 'DELETE':
            if not invoice:
                return jsonify({'error': 'Invoice not found'}), 404

            try:
                db.session.delete(invoice)
                db.session.commit()
                return jsonify({'message': 'Invoice deleted successfully'}), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to delete Invoice: {str(e)}'}), 500
            
@app.route('/newbills', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_newbillspayment():
    if request.method == 'GET':
        vendor_name = request.args.get('vendor_name')
        status = request.args.get('status')

        query = db.session.query(NewBill)

        if vendor_name:
            query = query.filter(NewBill.vendor_name.ilike(f'%{vendor_name}%'))

        if status:
            status_list = status.split(',')
            query = query.filter(NewBill.status.in_(status_list))

        bills = query.all()

        return jsonify([bill.to_dict() for bill in bills]), 200
    
@app.route('/newbillspayment/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def handle_new_bill(id):
    # Retrieve the bill
    bill = NewBill.query.filter_by(id=id).first()
    if not bill:
        return jsonify({'error': 'Bill does not exist'}), 404

    if request.method == 'GET':
        return jsonify(bill.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json
        if not data:
            return jsonify({'error': 'No data to update'}), 400

        # Update fields dynamically
        for key, value in data.items():
            setattr(bill, key, value)

        try:
            db.session.commit()
            return jsonify(bill.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update bill: {str(e)}'}), 500

    elif request.method == 'DELETE':
        try:
            db.session.delete(bill)
            db.session.commit()
            return jsonify({'message': 'Bill deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete bill: {str(e)}'}), 500

@app.route('/accounttypes', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_account_types():
    if request.method == "GET":
        type_name = request.args.get('type_name')

        if type_name:
            # Perform search by name
            accounts = AccountType.query.filter(AccountType.type_name.ilike(f'%{type_name}%')).all()
        else:
            # If no search term provided, return all items
            accounts = AccountType.query.all()

        return jsonify([account.to_dict() for account in accounts]), 200
    
    elif request.method == "POST":
        data = request.json
        print("Received data:", data)  # Debugging

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        required_fields = ['type_name']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        type_name = data.get('type_name')
        
        new_account_type = AccountType(
            type_name=type_name
        )

        try:
            db.session.add(new_account_type)
            db.session.commit()
            return jsonify(new_account_type.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create account hierarchy: {str(e)}'}), 500
        
@app.route('/accountcategories', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_account_categories():
        if request.method == "GET":
            category_name = request.args.get('category_name')

            if category_name:
                # Perform search by name
                accounts = AccountCategory.query.filter(AccountCategory.category_name.ilike(f'%{category_name}%')).all()
            else:
                # If no search term provided, return all items
                accounts = AccountCategory.query.all()

            return jsonify([account.to_dict() for account in accounts]), 200
        
        elif request.method == "POST":
            data = request.json
            print("Received data:", data)  # Debugging

            if not data:
                return jsonify({'error': 'No data provided for create'}), 400
            
            required_fields = ['category_name', 'type_name']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400

            type_name = data.get('type_name')
            category_name = data.get('category_name')

            type_name_id = AccountType.query.filter_by(type_name=type_name).first()
            if not type_name_id:
                return jsonify({'error': f'account with name {type_name} does not exist'}), 400


            new_account_category = AccountCategory(
                account_type_id=type_name_id.id,
                category_name=category_name,
                type_name=type_name
            )

            try:
                db.session.add(new_account_category)
                db.session.commit()
                return jsonify(new_account_category.to_dict()), 201
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to create account hierarchy: {str(e)}'}), 500      


import logging

        
@app.route('/paymentsreceived', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def handle_payments():
    if request.method == 'GET':
        payments = TransactionReceived.query.all()
        return jsonify([payment.to_dict() for payment in payments]), 200
    
    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        required_fields = ['customer_name', 'amount_received', 'payment_date', 'payment', 'payment_mode']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Extract and validate data
        customer_name = data.get('customer_name')
        amount_received = float(data.get('amount_received', 0))  # Convert to float
        date_str = data.get('payment_date')
        payment_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        payment = data.get('payment')
        payment_mode = data.get('payment_mode')
        customer_email = data.get('customer_email')
        customer_phone = data.get('customer_phone')
        customer_pin = data.get('customer_pin')
        currency = data.get('currency')

        # Create new payment record
        new_payment = TransactionReceived(
            customer_name=customer_name,
            amount_received=amount_received,
            payment_date=payment_date,
            payment=payment,
            payment_mode=payment_mode,
            customer_email=customer_email,
            currency=currency,
            customer_phone=customer_phone,
            customer_pin=customer_pin,
        )

        items_data = data.get('invoice_items')

        if not items_data:
            return jsonify({'error': 'No items provided for the invoice'}), 400

        # Define required fields once
        required_item_fields = ['invoice_id']

        for item_data in items_data:
            # Validate required fields
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            # Extract the invoice ID
            invoice_id = item_data.get('invoice_id')

            # Create a new invoice item
            new_invoice_item = TransactionReceivedInvoices(
                invoice_id=invoice_id,
            )

            # Add the item to the new payment's relationship
            new_payment.transaction_items.append(new_invoice_item)

        # Update customer records
        customer = Customer.query.filter_by(customer_name=customer_name).first()
        if not customer:
            return jsonify({'error': 'Customer does not exist'}), 400
        customer.total_amount_owed = max(0, customer.total_amount_owed - amount_received)
        customer.amount_paid += amount_received

        # Update balance sheet for Cash or Bank
        account_category_name = 'Cash at Hand' if payment_mode == 'Cash' else 'Cash at Bank'
        account_category = AccountCategory.query.filter_by(category_name=account_category_name).first()

        if account_category:
            account_category.amount += amount_received
            new_balancesheet = BalanceSheet(
                account_type_id=account_category.account_type_id,
                category_name=account_category_name,
                amount=amount_received,
                type_name=account_category.type_name,
                date=payment_date,
            )
            db.session.add(new_balancesheet)

        # Update Debtors
        debtor_account = AccountCategory.query.filter_by(category_name='Debtors').first()
        if debtor_account:
            debtor_account.amount -= amount_received
            amount_decrement = amount_received * -1
            new_balancesheet_debtor = BalanceSheet(
                account_type_id=debtor_account.account_type_id,
                category_name='Debtors',
                amount=amount_decrement,
                type_name=debtor_account.type_name,
                date=payment_date,
            )
        db.session.add(new_balancesheet_debtor)

        # Update Cash Book
        cash_account = TransactionReceived.query.filter_by(payment_mode='Cash').first()
        if cash_account:
            new_cashbook = CashBook(
                item_details=customer_name,
                bank='BANK',
                cash_amount=amount_received,
                date=payment_date,
            )
            db.session.add(new_cashbook)
        else:
            new_cashbook = CashBook(
                item_details=customer_name,
                bank='BANK',
                bank_amount=amount_received,
                date=payment_date,
            )
            db.session.add(new_cashbook)

        try:
            db.session.add(new_payment)
            db.session.commit()
            return jsonify(new_payment.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500

@app.route('/paymentsreceived/<int:id>', methods=['GET', 'POST', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def handle_specific_payments(id):
    if request.method == 'GET':
        payment = TransactionReceived.query.get(id)
        if not payment:
            return jsonify({'error': 'Payment not found'}), 404
        
        return jsonify(payment.to_dict()), 200
    
    elif request.method == 'DELETE':
        payment = TransactionReceived.query.get(id)
        if not payment:
            return jsonify({'error': 'Payment not found'}), 404
        
        try:
            db.session.delete(payment)
            db.session.commit()
            return jsonify({'message': 'Payment deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete payment: {str(e)}'}), 500

@app.route('/paymentsmade', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def handle_paymentsmade():
        if request.method == 'GET':
            payments = PaymentMade.query.all()
            return jsonify([payment.to_dict() for payment in payments]), 200
        
        elif request.method == 'POST':
            data = request.json

            if not data:
                return jsonify({'error': 'No data provided for create'}), 400
            
            required_fields = ['vendor_name', 'payment_amount', 'payment_date', 'payment_mode', 'payment']
            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400

            # Extract data from the request
            vendor_name = data.get('vendor_name')
            vendor_email = data.get('vendor_email')
            vendor_phone = data.get('vendor_phone')
            vendor_pin = data.get('vendor_pin')
            payment_amount = float(data.get('payment_amount', 0))  # Convert to float
            payment_date_str = data.get('payment_date')
            payment_date = datetime.strptime(payment_date_str, '%Y-%m-%d').date()
            payment = data.get('payment')
            payment_mode = data.get('payment_mode')
            currency = data.get('currency')

            # Create new payment record
            new_payment = PaymentMade(
                vendor_name=vendor_name,
                vendor_phone=vendor_phone,
                vendor_email=vendor_email,
                vendor_pin=vendor_pin,
                payment_amount=payment_amount,
                payment_date=payment_date,
                payment=payment,
                currency=currency,
                payment_mode=payment_mode,
            )

            items_data = data.get('bill_items')

            if not items_data:
                return jsonify({'error': 'No items provided for the invoice'}), 400

            # Define required fields once
            required_item_fields = ['bill_id']

            for item_data in items_data:
                # Validate required fields
                for field in required_item_fields:
                    if field not in item_data:
                        return jsonify({'error': f'Missing required field in item: {field}'}), 400

                # Extract the invoice ID
                bill_id = item_data.get('bill_id')

                # Create a new invoice item
                new_bill_item = PaymentMadeBill(
                    bill_id=bill_id,
                )

                # Add the item to the new payment's relationship
                new_payment.bill_items.append(new_bill_item)

            # Update vendor records
            vendor = Vendor.query.filter_by(vendor_name=vendor_name).first()
            if vendor:
                vendor.total_amount_owed = max(0, vendor.total_amount_owed - payment_amount)
                vendor.amount_paid += payment_amount
            else:
                return jsonify({'error': 'Vendor does not exist'}), 400

            if payment_mode == 'Cash':
                cash_hand_account = AccountCategory.query.filter_by(category_name='Cash at Hand').first()
                if cash_hand_account:
                    cash_hand_account.amount += float(payment_amount)
                    made = float(payment_amount) * -1
                    new_balancesheet = BalanceSheet(
                        account_type_id=cash_hand_account.account_type_id,
                        category_name='Cash at Hand',
                        amount=made,
                        type_name=cash_hand_account.type_name,
                        date=payment_date,
                    )
                    db.session.add(new_balancesheet)
            else:
                cash_bank_account = AccountCategory.query.filter_by(category_name='Cash at Bank').first()
                if cash_bank_account:
                    cash_bank_account.amount += float(payment_amount)
                    made_bank = float(payment_amount) * -1
                    new_balancesheet = BalanceSheet(
                        account_type_id=cash_bank_account.account_type_id,
                        category_name='Cash at Bank',
                        amount=made_bank,
                        type_name=cash_bank_account.type_name,
                        date=payment_date,
                    )
                    db.session.add(new_balancesheet)            
            

            # Update Creditors
            debtor_account = AccountCategory.query.filter_by(category_name='Creditors').first()
            if debtor_account:
                debtor_account.amount -= float(payment_amount)
                amount_ = float(payment_amount) * -1
                new_balancesheet = BalanceSheet(
                    account_type_id=debtor_account.account_type_id,
                    category_name='Creditors',
                    amount=amount_,
                    type_name=debtor_account.type_name,
                    date=payment_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
            

            # Update Cash Book
            cash_account = PaymentMade.query.filter_by(payment_mode='Cash').first()
            if cash_account:
                    new_cashbookdebit = CashBookDebit(
                        item_details = vendor_name,
                        bank = 'BANK',
                        cash_amount=payment_amount,
                        date = payment_date,
                    )
                    db.session.add(new_cashbookdebit)
            else:
                    new_cashbookdebit = CashBookDebit(
                            item_details = vendor_name,
                            bank = 'BANK',
                            bank_amount=payment_amount,
                            date = payment_date,
                        )
                    db.session.add(new_cashbookdebit)

        try:
            db.session.add(new_payment)
            db.session.commit()
            return jsonify(new_payment.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500
        
@app.route('/paymentsmade/<int:id>', methods=['GET', 'PATCH'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_patch_payments(id):
    # Handle the GET request to fetch the quote by quote_number
    if request.method == 'GET':
        quote = PaymentMade.query.filter_by(payment=id).first()

        # If quote is not found, return 404
        if not quote:
            return jsonify({'error': 'Quote not found'}), 404

        # Convert the quote object to a dictionary and return it
        return jsonify(quote.to_dict()), 200

@app.route('/accounttypes', methods=['GET'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_accounttypes_details():
    if request.method == 'GET':
        accounts = AccountType.query.all()
        return jsonify([account.to_dict() for account in accounts])
    if not accounts:
        return jsonify({'error': 'Accounts not found'}), 404
    
@app.route('/accounttypes/<type_name>', methods=['GET'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_account_types_by_type_name(type_name):
    account = AccountType.query.filter_by(type_name=type_name).first()
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    
    return jsonify(account.to_dict()), 200

@app.route('/accountcategories/<category_name>', methods=['GET'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_account_subcategories_by_type_name(category_name):
    account = AccountCategory.query.filter_by(category_name=category_name).first()
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    
    return jsonify(account.to_dict()), 200


@app.route('/accounts/<type_name>', methods=['GET'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_account_details(type_name):
    account = AccountType.query.filter_by(type_name=type_name).first()
    if not account:
        return jsonify({'error': 'Account not found'}), 404
    
    return jsonify(account.to_dict()), 200

@app.route('/vendors/<int:id>', methods=['GET', 'PATCH'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def vendor_details(id):
    vendor = Vendor.query.filter_by(id=id).first()

    if not vendor:
        return jsonify({'error': 'Vendor not found'}), 404

    if request.method == 'GET':
        return jsonify(vendor.to_dict()), 200

    if request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data to update'}), 400

        for key, value in data.items():
            if hasattr(vendor, key):  # Check if the attribute exists
                setattr(vendor, key, value)

        try:
            db.session.commit()
            return jsonify({'message': 'Vendor updated successfully', 'vendor': vendor.to_dict()}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Failed to update vendor', 'details': str(e)}), 500


@app.route('/customers/<int:id>', methods=['GET', 'PATCH'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_customer_details(id):
    customer = Customer.query.filter_by(id=id).first()
    if not customer:
        return jsonify({'error': 'Customer not found'}), 404

    if request.method == 'GET':
        return jsonify(customer.to_dict()), 200

    if request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data to update'}), 400

        for key, value in data.items():
            if hasattr(customer, key):  # Check if the attribute exists
                setattr(customer, key, value)

        try:
            db.session.commit()
            return jsonify({'message': 'Customer updated successfully', 'customer': customer.to_dict()}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Failed to update customer', 'details': str(e)}), 500

@app.route('/retreadshoptrips/<trip_number>', methods=['GET'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_retread_trip_details(trip_number):
    trip = RetreadTyreTrip.query.filter_by(trip_number=trip_number).first()
    if not trip:
        return jsonify({'error': 'Customer not found'}), 404
    
    return jsonify(trip.to_dict()), 200

@app.route('/vehiclemantainances/<repair_number>', methods=['GET'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_mantainance_details(repair_number):
    mantainance = VehicleMantainance.query.filter_by(repair_number=repair_number).first()
    if not mantainance:
        return jsonify({'error': 'Mantainance not found'}), 404
    
    print(mantainance.to_dict())  # Debugging output
    return jsonify(mantainance.to_dict()), 200


@app.route('/truck/<vehicle_id>', methods=['GET'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_truck_detailsby_truck_number(vehicle_id):
    truck = Truck.query.filter_by(vehicle_id=vehicle_id).first()
    if not truck:
        return jsonify({'error': 'Truck not found'}), 404
    
    return jsonify(truck.to_dict()), 200
        
@app.route('/retreadtyresremove', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_retreadtyresremove():
    if request.method == 'GET':  
        truck_number = request.args.get('truck_number')

        if truck_number:
            # Perform search by truck number
            inventory_items = RemoveRetreadtyre.query.filter(RemoveRetreadtyre.truck_number.ilike(f'%{truck_number}%')).all()
        else:
            # If no search term provided, return all items
            inventory_items = RemoveRetreadtyre.query.all()

        return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200
        
    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        # Input validation
        required_fields = ['name', 'size', 'starting_mileage', 'truck_number', 'serial_number', 'position', 'date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        name = data.get('name')
        size = data.get('size')
        starting_mileage = data.get('starting_mileage')
        truck_number = data.get('truck_number')
        serial_number = data.get('serial_number')
        position = data.get('position')
        status = data.get('status')
        price = data.get('price')

        # Convert date string to Python date object
        date_str = data.get('date')
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

        truck = Truck.query.filter_by(truck_number=truck_number).first()
        if not truck:
            return jsonify({'error': f'Truck with number {truck_number} does not exist'}), 400

        new_retreadtyreremove = RemoveRetreadtyre(
            truck_id=truck.id,
            name=name,
            size=size,
            date=date,
            serial_number=serial_number,
            truck_number=truck_number,
            starting_mileage=starting_mileage,
            position=position,
            status=status,
            price= 12000,
        )
        
        used_tyre = OldTyres.query.filter_by(serial_number=serial_number).first()
        if used_tyre:
            used_tyre.status = 'Fitted'
            used_tyre.retread_status = 'Fitted'
        else:
            return jsonify({'error': 'Tyre does not exist or is not available'}), 400

        try:
            db.session.add(new_retreadtyreremove)
            db.session.commit()
            return jsonify(new_retreadtyreremove.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500

        
@app.route('/retreadtyresremove/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_retreadtyreremove_by_id(id):
    session = db.session()
    retreadtyre = session.get(RemoveRetreadtyre, id)

    if request.method == 'GET':
        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(retreadtyre.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400


        for key, value in data.items():
            setattr(retreadtyre, key, value)

        try:
            db.session.commit()
            return jsonify(retreadtyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500
        
@app.route('/fitusedtyres', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_fitusedtyres():
    if request.method == 'GET':
        serial_number = request.args.get('serial_number')

        if serial_number:
            # Perform search by serial number
            inventory_items = FitUsedTyre.query.filter(FitUsedTyre.serial_number.ilike(f'%{serial_number}%')).all()
        else:
            # If no search term provided, return all items
            inventory_items = FitUsedTyre.query.all()

        return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200
        
    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        # Input validation
        required_fields = ['item_details', 'size', 'final_mileage','truck_number','starting_mileage', 'reason','truck_number', 'serial_number', 'tyre_mileage','position','date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        item_details = data.get('item_details')
        size = data.get('size')
        serial_number = data.get('serial_number')
        truck_number = data.get('truck_number')
        starting_mileage = data.get('starting_mileage')
        status = data.get('status')
        position = data.get('position')
        
        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        truck = Truck.query.filter_by(truck_number=truck_number).first()
        if not truck:
            return jsonify({'error': f'Account with name {truck_number} does not exist'}), 400

        new_usedtyre =FitUsedTyre(
            item_details = item_details,
            size = size,
            serial_number = serial_number,
            truck_number = truck_number,
            starting_mileage = starting_mileage,
            status = status,
            position = position,
        )

        # Find the existing tyre and update its status
        used_tyre = OldTyres.query.filter_by(serial_number=serial_number).first()
        if used_tyre:
            used_tyre.status = 'Fitted'

        try:
            db.session.add(new_usedtyre)
            db.session.commit()
            return jsonify(new_usedtyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500
        
@app.route('/unfitusedtyres', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_unfitusedtyres():
    if request.method == 'GET':  
        serial_number = request.args.get('serial_number')
        if serial_number:
            inventory_items = UnfitRetreadtyre.query.filter(UnfitRetreadtyre.serial_number.ilike(f'%{serial_number}%')).all()
        else:
            inventory_items = UnfitRetreadtyre.query.all()
        return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200
        
    elif request.method == 'POST':
        data = request.json
        print("Received data:", data)  # Debugging line

        if not data:
            return jsonify({'error': 'No data provided for update'}), 400

        # Input validation
        required_fields = ['name', 'size', 'starting_mileage', 'truck_number', 'serial_number', 'position', 'date']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required field(s): {", ".join(missing_fields)}'}), 400

        # Extract fields
        name = data.get('name')
        size = data.get('size')
        starting_mileage = data.get('starting_mileage')
        truck_number = data.get('truck_number')
        serial_number = data.get('serial_number')
        position = data.get('position')
        reason = data.get('reason')
        final_mileage = data.get('final_mileage')
        tyre_mileage = data.get('tyre_mileage')
        condition = data.get('condition')

        # Convert date string to Python date object
        date_str = data.get('date')
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400
        
        tyre = RemoveRetreadtyre.query.filter_by(serial_number=serial_number, status='FITTED').first()
        if tyre:
            tyre.status = 'UNFITTED'

        fitted_used_tyre = FitUsedTyre.query.filter_by(serial_number=serial_number, status='FITTED').first()
        if fitted_used_tyre:
            fitted_used_tyre.status = 'UNFITTED'

        # Find the existing tyre and update its status
        used_tyre = OldTyres.query.filter_by(serial_number=serial_number).first()
        if used_tyre:
            used_tyre.retread_status = 'NOT AVAILABLE'
            used_tyre.condition = condition
            used_tyre.status = 'Store'
            used_tyre.reason = reason
            used_tyre.position = position
            used_tyre.date = date
            used_tyre.truck_number = truck_number
            (used_tyre.tyre_mileage) += int(tyre_mileage)
            # Commit the changes to the database
            try:
                db.session.commit()
                return jsonify(used_tyre.to_dict()), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to update tyre record: {str(e)}'}), 500
        else:
            return jsonify({'error': 'Tyre does not exist or is not available'}), 400
        
@app.route('/usedtyres', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_usedtyres():
    if request.method == 'GET':
        serial_number = request.args.get('serial_number')

        if serial_number:
            # Perform search by serial number
            inventory_items = OldTyres.query.filter(OldTyres.serial_number.ilike(f'%{serial_number}%')).all()
        else:
            # If no search term provided, return all items
            inventory_items = OldTyres.query.all()

        return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200
        
    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        # Input validation
        required_fields = ['item_details', 'size', 'serial_number','truck_number','position', 'status', 'date', 'starting_mileage']

        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        item_details = data.get('item_details')
        size = data.get('size')
        tyre_mileage = data.get('tyre_mileage')
        starting_mileage = data.get('starting_mileage')
        final_mileage = data.get('final_mileage')
        serial_number = data.get('serial_number')
        position = data.get('position')
        reason = data.get('reason')
        truck_number = data.get('truck_number')
        retread_counter = data.get('retread_counter')
        status = data.get('status')
        condition = data.get('condition')
        retread_status = data.get('retread_status')

        
        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        truck = Truck.query.filter_by(truck_number=truck_number).first()
        if not truck:
            return jsonify({'error': f'Account with name {truck_number} does not exist'}), 400

        new_usedtyre =OldTyres(
            truck_id = truck.id,
            item_details =item_details,
            size=size,
            tyre_mileage = tyre_mileage,
            retread_counter=retread_counter,
            date = date,
            truck_number = truck_number,
            serial_number =serial_number,
            starting_mileage = starting_mileage,
            final_mileage=final_mileage,
            retread_status = retread_status,
            position = position,
            reason=reason,
            status=status,
            condition=condition,
        )

        try:
            db.session.add(new_usedtyre)
            db.session.commit()
            return jsonify(new_usedtyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500

        
@app.route('/usedtyres/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_usedtyre_by_id(id):
    session = db.session()
    retreadtyre = session.get(OldTyres, id)

    if request.method == 'GET':
        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(retreadtyre.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400


        for key, value in data.items():
            setattr(retreadtyre, key, value)

        try:
            db.session.commit()
            return jsonify(retreadtyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500
        
    elif request.method == 'DELETE':
        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404

        try:
            db.session.delete(retreadtyre)
            db.session.commit()
            return jsonify({'message': 'Item deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete item: {str(e)}'}), 500
        
@app.route('/unfitretreadtyres', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_unfitretreadtyres():
    if request.method == 'GET':  
        serial_number = request.args.get('serial_number')
        if serial_number:
            inventory_items = UnfitRetreadtyre.query.filter(UnfitRetreadtyre.serial_number.ilike(f'%{serial_number}%')).all()
        else:
            inventory_items = UnfitRetreadtyre.query.all()
        return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200
        
    elif request.method == 'POST':
        data = request.json
        print("Received data:", data)  # Debugging line

        if not data:
            return jsonify({'error': 'No data provided for update'}), 400

        # Input validation
        required_fields = ['name', 'size', 'starting_mileage', 'truck_number', 'serial_number', 'position', 'date']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required field(s): {", ".join(missing_fields)}'}), 400

        # Extract fields
        name = data.get('name')
        size = data.get('size')
        starting_mileage = data.get('starting_mileage')
        truck_number = data.get('truck_number')
        serial_number = data.get('serial_number')
        position = data.get('position')
        reason = data.get('reason')
        final_mileage = data.get('final_mileage')
        tyre_mileage = data.get('tyre_mileage')
        condition = data.get('condition')

        # Convert date string to Python date object
        date_str = data.get('date')
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400
        
        tyre = RemoveRetreadtyre.query.filter_by(serial_number=serial_number, status='FITTED').first()
        if tyre:
            tyre.status = 'UNFITTED'

        # Find the existing tyre and update its status
        used_tyre = OldTyres.query.filter_by(serial_number=serial_number).first()
        if used_tyre:
            used_tyre.retread_status = 'NOT AVAILABLE'
            used_tyre.condition = condition
            used_tyre.status = 'Store'
            used_tyre.reason = reason
            used_tyre.position = position
            used_tyre.date = date
            used_tyre.truck_number = truck_number
            used_tyre.tyre_mileage += int(tyre_mileage)
            # Commit the changes to the database
            try:
                db.session.commit()
                return jsonify(used_tyre.to_dict()), 200
            except Exception as e:
                db.session.rollback()
                return jsonify({'error': f'Failed to update tyre record: {str(e)}'}), 500
        else:
            return jsonify({'error': 'Tyre does not exist or is not available'}), 400

        
@app.route('/retreadtyres/<string:serial_number>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_retreadtyres_by_serial_number(serial_number):

    retreadtyre = RetreadTyre.query.filter_by(serial_number=serial_number).first()

    if request.method == 'GET':
        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(retreadtyre.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

        for key, value in data.items():
            setattr(retreadtyre, key, value)

        try:
            session.commit()
            return jsonify(retreadtyre.to_dict()), 200
        except Exception as e:
            session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500
        
    elif request.method == 'DELETE':
        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404

        try:
            session.delete(retreadtyre)
            session.commit()
            return jsonify({'message': 'Item deleted successfully'}), 200
        except Exception as e:
            session.rollback()
            return jsonify({'error': f'Failed to delete item: {str(e)}'}), 500
        
@app.route('/retreadtyresremove/<string:serial_number>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_unfitretreadtyres_by_id(serial_number):
    # Use filter_by to handle serial_number lookup
    tyre = RemoveRetreadtyre.query.filter_by(serial_number=serial_number).first()

    if request.method == 'GET':
        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(tyre.to_dict()), 200
    
    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

        for key, value in data.items():
            setattr(tyre, key, value)

        try:
            db.session.commit()
            return jsonify(tyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500


@app.route('/retreadtyresupdate', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_retreadtyresupdate():
    if request.method == 'GET':  
        name = request.args.get('name')

        if name:
            # Perform search by name
            inventory_items = RetreadTyreupdate.query.filter(RetreadTyreupdate.name.ilike(f'%{name}%')).all()
        else:
            # If no search term provided, return all items
            inventory_items = RetreadTyreupdate.query.all()

        return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200
        
    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        # Input validation
        required_fields = ['name', 'description', 'quantity', 'date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        name = data.get('name')
        size = data.get('size')
        serial_number = data.get('serail_number')
        quantity = data.get('quantity')

        
        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        new_retreadtyreupdate = RetreadTyreupdate(
            name =name,
            quantity = quantity,
            date = date,
            serial_number = serial_number,
            size = size,
        )

        try:
            db.session.add(new_retreadtyreupdate)
            db.session.commit()
            return jsonify(new_retreadtyreupdate.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500

        
@app.route('/retreadtyresupdate/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_retreadtyreupdate_by_id(id):
    session = db.session()
    retreadtyre = session.get(RetreadTyreupdate, id)

    if request.method == 'GET':
        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(retreadtyre.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400


        for key, value in data.items():
            setattr(retreadtyre, key, value)

        try:
            db.session.commit()
            return jsonify(retreadtyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500
        
@app.route('/retreadtyres', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_retreadtyres():
    if request.method == 'GET':
        serial_number = request.args.get('serial_number')
        status = request.args.get('status')

        query = db.session.query(RetreadTyre)

        if serial_number:
            query = query.filter(RetreadTyre.serial_number.ilike(f'%{serial_number}%'))

        if status:
            query = query.filter(RetreadTyre.status.ilike(f'%{status}%'))

        retread_tyres = query.all()

        return jsonify([retread_tyre.to_dict() for retread_tyre in retread_tyres]), 200

    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        # Input validation
        required_fields = ['name', 'size', 'serial_number', 'tyre_mileage','date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        name = data.get('name')
        size = data.get('size')
        tyre_mileage = data.get('tyre_mileage')
        serial_number = data.get('serial_number')
        status = data.get('status')

        # Convert date string to Python date object
        date_str = data.get('date')
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError as e:
            return jsonify({'error': f'Invalid date format: {date_str}. Expected format: YYYY-MM-DD'}), 400

        new_retreadtyre = RetreadTyre(
            name=name,
            tyre_mileage=tyre_mileage,
            date=date,
            size=size,
            serial_number=serial_number,
            status=status,
        )

        tyre = OldTyres.query.filter_by(serial_number=serial_number).first()
        if tyre:
                tyre.retread_counter += 1
        else:
                return jsonify({'error': f'Tyre Does Not Exist'}), 400

        try:
            db.session.add(new_retreadtyre)
            db.session.commit()
            return jsonify(new_retreadtyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            logging.error(f'Failed to create item: {str(e)}')
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500


@app.route('/retreadtyres/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_retreadtyres_by_id(id):
    with db.session() as session:
        retreadtyre = session.get(RetreadTyre, id)

    if request.method == 'GET':
        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(retreadtyre.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

        for key, value in data.items():
            setattr(retreadtyre, key, value)

        try:
            session.commit()
            return jsonify(retreadtyre.to_dict()), 200
        except Exception as e:
            session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500
        
    elif request.method == 'DELETE':
        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404

        try:
            session.delete(retreadtyre)
            session.commit()
            return jsonify({'message': 'Item deleted successfully'}), 200
        except Exception as e:
            session.rollback()
            return jsonify({'error': f'Failed to delete item: {str(e)}'}), 500
                    
@app.route('/retreadedtyres', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_retreadedtyres():
    if request.method == 'GET':  
        serial_number = request.args.get('serial_number')

        if serial_number:
            # Perform search by name
            inventory_items = RetreadedTyre.query.filter(RetreadedTyre.serial_number.ilike(f'%{serial_number}%')).all()
        else:
            # If no search term provided, return all items
            inventory_items = RetreadedTyre.query.all()

        return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200
        
    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        # Input validation
        required_fields = ['name', 'size', 'serial_number','tyre_mileage', 'starting_mileage', 'final_mileage', 'truck_number', 'position', 'date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        name = data.get('name')
        size = data.get('size')
        tyre_mileage = data.get('tyre_mileage')
        starting_mileage = data.get('starting_mileage')
        final_mileage = data.get('final_mileage')
        truck_number = data.get('truck_number')
        serial_number = data.get('serial_number')
        position = data.get('position')
        status = data.get('status')
        price = data.get('price')

        
        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        new_retreadtyre = RetreadedTyre(
            name =name,
            tyre_mileage = tyre_mileage,
            final_mileage = final_mileage,
            starting_mileage = starting_mileage,
            truck_number = truck_number,
            position = position,
            date = date,
            price = price,
            size = size,
            serial_number = serial_number,
            status=status,
        )

        try:
            db.session.add(new_retreadtyre)
            db.session.commit()
            return jsonify(new_retreadtyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500


@app.route('/retreadedtyres/<string:serial_number>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_retreadedtyres_by_id(serial_number):

    retreadtyre = RetreadedTyre.query.filter_by(serial_number=serial_number).first()

    if request.method == 'GET':
        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(retreadtyre.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400


        for key, value in data.items():
            setattr(retreadtyre, key, value)

        try:
            db.session.commit()
            return jsonify(retreadtyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500
        
    elif request.method == 'DELETE':
                    if not retreadtyre:
                        return jsonify({'error': 'Item not found'}), 404

                    try:
                        db.session.delete(retreadtyre)
                        db.session.commit()
                        return jsonify({'message': 'Item deleted successfully'}), 200
                    except Exception as e:
                        db.session.rollback()
                        return jsonify({'error': f'Failed to delete item: {str(e)}'}), 500
                    

@app.route('/retreadtyres/<string:serial_number>', methods=['GET','DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_retreadtyre_by_serial_number(serial_number):
    session = db.session()
    # Query the database for the retread tyre by its serial number
    retreadtyre = session.query(RetreadTyre).filter_by(serial_number=serial_number).first()

    if request.method == 'GET':
        if not retreadtyre:
            return jsonify({'error': 'Item not found'}), 404

        return jsonify(retreadtyre.to_dict()), 200
    
    elif request.method == 'DELETE':
                    if not retreadtyre:
                        return jsonify({'error': 'Item not found'}), 404

                    try:
                        db.session.delete(retreadtyre)
                        db.session.commit()
                        return jsonify({'message': 'Item deleted successfully'}), 200
                    except Exception as e:
                        db.session.rollback()
                        return jsonify({'error': f'Failed to delete item: {str(e)}'}), 500        

        
@app.route('/totals', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_totals():
    if request.method == 'GET':
        totals = Total.query.all()
        return jsonify([total.to_dict() for total in totals]), 200
    
    elif request.method == 'POST':
        data = request.args

        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        required_fields = ['account_name', 'amount']
        
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        account_name = data.get('account_name')
        amount = data.get('amount')

        try:
            amount = float(amount)  # Convert amount to float, add error handling if necessary
        except ValueError:
            return jsonify({'error': 'Amount must be a number'}), 400

        new_total = Total(
            account_name=account_name,
            amount=amount,
        )
        try:
            db.session.add(new_total)  # Assuming db is the SQLAlchemy instance
            db.session.commit()
            return jsonify({'message': 'New total added successfully'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
        
@app.route('/purchases', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_purchases():
    if request.method == 'GET':  
        supplier_name = request.args.get('supplier_name')

        if supplier_name:
            # Perform search by name
            inventory_items = Purchase.query.filter(Purchase.supplier_name.ilike(f'%{supplier_name}%')).all()
        else:
            # If no search term provided, return all items
            inventory_items = Purchase.query.all()

        return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200
        
    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        # Input validation
        required_fields = ['name', 'description', 'quantity', 'date', 'email', 'vat', 'supplier_name', 'supplier_pin', 'credit', 'terms']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        name = data.get('name')
        description = data.get('description')
        quantity = data.get('quantity')
        price = data.get('price')
        email = data.get("email")
        vat = data.get('vat')
        supplier_name = data.get('supplier_name')
        supplier_pin = data.get('supplier_pin')
        credit = data.get('credit')
        terms = data.get('terms')
        
        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        new_purchase = Purchase(
            name=name,
            description=description,
            quantity=quantity,
            date=date,
            price=price,
            email=email,
            vat=vat,
            supplier_name=supplier_name,
            supplier_pin=supplier_pin,
            credit=credit,
            terms=terms,
        )

        try:
            db.session.add(new_purchase)
            db.session.commit()
            return jsonify(new_purchase.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500


@app.route('/purchases/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_purchases_by_id(id):
    session = db.session()
    purchase = session.get(Purchase, id)

    if request.method == 'GET':
        if not purchase:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(purchase.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not purchase:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400


        for key, value in data.items():
            setattr(purchase, key, value)

        try:
            db.session.commit()
            return jsonify(purchase.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500

        
@app.route('/stores', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_store_items():
    if request.method == 'GET':  
        date = request.args.get('date')  # Corrected syntax
        if date:
            # Assuming your Store model has a date field named 'date'
            inventory_items = Store.query.filter(Store.date.ilike(f'%{date}%')).all()
        else:
            inventory_items = Store.query.all()
        return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200

        
    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        # Input validation
        required_fields = ['item_details','quantity', 'date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        item_details = data.get('item_details')
        quantity = data.get('quantity')
        truck_number=data.get('truck_number')
        mechanic = data.get('mechanic')
        price = data.get('price')
        spare_category = data.get('spare_category')
        description = data.get('description')
        
        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        truck = Truck.query.filter_by(truck_number=truck_number).first()
        if not truck:
            return jsonify({'error': f'Account with name {truck_number} does not exist'}), 400

        removed_item = Store(
            truck_id=truck.id,
            item_details=item_details,
            price=price,
            spare_category=spare_category,
            description=description,
            truck_number=truck_number,
            quantity=quantity,
            date=date,
            mechanic=mechanic,
        )

        spare = SpareSubCategory.query.filter_by(spare_subcategory_name=item_details).first()
        if spare:
            spare.quantity -= float(quantity)
        else:
            return jsonify({'error': f'{spare} does not exist'}), 400

        try:
            db.session.add(removed_item)
            db.session.commit()
            return jsonify(removed_item.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500
    

@app.route('/stores/<int:id>', methods=['GET'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_store_items_by_id(id):
    item = Store.query.get(id)

    if request.method == 'GET':
        if not item:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(item.to_dict()), 200


@app.route('/updates', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_update_items():
    if request.method == 'GET':  
            date = request.args.get('date')  # Corrected syntax
            if date:
                # Assuming your Store model has a date field named 'date'
                inventory_items = Update.query.filter(Update.date.ilike(f'%{date}%')).all()
            else:
                inventory_items = Update.query.all()
            return jsonify([inventory_item.to_dict() for inventory_item in inventory_items]), 200

        
    elif request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        # Input validation
        required_fields = ['item_details', 'quantity', 'date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        item_details = data.get('item_details')
        quantity = data.get('quantity')
        
        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        updated_item = Update(
            item_details=item_details,
            quantity=quantity,
            date=date,
        )

        try:
            db.session.add(updated_item)
            db.session.commit()
            return jsonify(updated_item.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500
        

@app.route('/updates/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_update_items_by_id(id):
    item = Update.query.get(id)

    if request.method == 'GET':
        if not item:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(item.to_dict()), 200
    

@app.route('/tyres', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_tyres():
    if request.method == 'GET':  
            item_details = request.args.get('item_details')  # Corrected syntax
            if item_details:
                # Assuming your Store model has a date field named 'date'
                tyres = Tyre.query.filter(Tyre.item_details.ilike(f'%{item_details}%')).all()
            else:
                tyres= Tyre.query.all()
            return jsonify([tyre.to_dict() for tyre in tyres]), 200

    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        # Input validation
        required_fields = ['item_details','quantity']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        

        item_details = data.get('item_details')
        quantity = data.get('quantity')
        price = data.get('price')

        # Convert date string to Python date object
        # date_str = data.get('date')
        # date = datetime.strptime(date_str, '%Y-%m-%d').date()

        new_tyre = Tyre(
            item_details=item_details,
            quantity = quantity,
            price=price,
        )

        try:
            db.session.add(new_tyre)
            db.session.commit()
            return jsonify(new_tyre.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create item: {str(e)}'}), 500

@app.route('/tyres/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_tyres_by_id(id):
    tyre = Tyre.query.get(id)

    if request.method == 'GET':
        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(tyre.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 400

        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

        # Update fields dynamically
        for key, value in data.items():
            setattr(tyre, key, value)

        try:
            db.session.commit()
            return jsonify(tyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500

    elif request.method == 'DELETE':
        if not tyre:
            return jsonify({'error': 'Item not found'}), 404

        try:
            db.session.delete(tyre)
            db.session.commit()
            return jsonify({'success': f'Tyre with ID {id} has been deleted'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete item: {str(e)}'}), 500


@app.route('/removetyres', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_removetyres():
    if request.method == 'GET':  
        tyres = Removetyre.query.all()
        return jsonify([tyre.to_dict() for tyre in tyres]), 200

    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        # Input validation
        required_fields = ['item_details', 'quantity', 'status', 'truck_number', 'serial_number', 'starting_mileage', 'date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Extract data fields
        item_details = data.get('item_details')
        size = data.get('size')
        quantity = data.get('quantity')
        starting_mileage = data.get('starting_mileage')
        truck_number = data.get('truck_number')
        serial_number = data.get('serial_number')
        position = data.get('position')
        status = data.get('status')
        price = data.get('price')
        date_str = data.get('date')
        
        try:
            # Convert date string to Python date object
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Expected YYYY-MM-DD'}), 400

        truck = Truck.query.filter_by(truck_number=truck_number).first()
        if not truck:
            return jsonify({'error': f'Truck with number {truck_number} does not exist'}), 400
        
        # Check if tyre exists and has sufficient quantity
        tyre = Tyre.query.filter_by(size=size, item_details=item_details).first()
        if tyre is None:
            return jsonify({'error': f'{item_details} with size {size} does not exist'}), 400

        try:
            requested_quantity = float(quantity)
            if tyre.quantity < requested_quantity:
                return jsonify({'error': f'Insufficient quantity of {item_details}. Only {tyre.quantity} units available'}), 400
        except ValueError:
            return jsonify({'error': 'Invalid quantity provided'}), 400

        # Create new `Removetyre` record
        new_tyre = Removetyre(
            truck_id=truck.id,
            item_details=item_details,
            size=size,
            quantity=quantity,
            date=date,
            serial_number=serial_number,
            truck_number=truck_number,
            starting_mileage=starting_mileage,
            position=position,
            status=status,
            price=price,
        )

        try:
            # Update tyre quantity and add new_tyre in one transaction
            tyre.quantity -= requested_quantity
            db.session.add(new_tyre)
            db.session.commit()
            return jsonify(new_tyre.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to process request: {str(e)}'}), 500

@app.route('/removetyres/<string:serial_number>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_Removetyres_by_id(serial_number):
    # Use filter_by to handle serial_number lookup
    tyre = Removetyre.query.filter_by(serial_number=serial_number).first()

    if request.method == 'GET':
        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(tyre.to_dict()), 200
    
    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

        for key, value in data.items():
            setattr(tyre, key, value)

        try:
            db.session.commit()
            return jsonify(tyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500

@app.route('/banks', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app"])
def get_and_post_bank():
    if request.method == 'GET':
        banks= BankAccount.query.all()
        return jsonify([bank.to_dict() for bank in banks]), 201

    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        # Input validation
        required_fields = ['bank_name']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        bank_name = data.get('bank_name')
        bank_details = data.get('bank_details')
        amount = data.get('amount')
        currency = data.get('currency')

        new_bank = BankAccount(
            bank_name = bank_name,
            bank_details=bank_details,
            amount=amount,
            currency=currency,
        )

        # Update Cash at Bank
        bank_account = AccountCategory.query.filter_by(category_name='Cash at Bank').first()
        if bank_account:
                bank_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=bank_account.account_type_id,
                    category_name='Cash at Bank',
                    amount=float(amount),
                    type_name=bank_account.type_name,
                    date=datetime.today().date(),
                )
                db.session.add(new_balancesheet)
        else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
        
        fund = Funds.query.filter_by(fund_name='Bank').first()
        if fund:
            fund.amount += float(amount)
        else:
            return jsonify({'error': f'Missing required field: {field}'}), 400

        try:
            db.session.add(new_bank)
            db.session.commit()
            return jsonify(new_bank.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Bank Account: {str(e)}'}), 500
        
@app.route('/bankaccounts', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app"])
def get_and_post_bank_accounts():
    if request.method == 'GET':
        banks= BankItem.query.all()
        return jsonify([bank.to_dict() for bank in banks]), 201

    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        # Input validation
        required_fields = ['bank_name', 'amount','currency']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        

        bank_name = data.get('bank_name')
        bank_details = data.get('bank_details')
        amount = data.get('amount')
        currency = data.get('currency')

        new_bank = BankItem(
            bank_name = bank_name,
            bank_details=bank_details,
            currency=currency,
            amount=amount,
        )
    
        # Update Cash at Bank
        bank_account = AccountCategory.query.filter_by(category_name='Cash at Bank').first()
        if bank_account:
                bank_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=bank_account.account_type_id,
                    category_name='Cash at Bank',
                    amount=float(amount),
                    type_name=bank_account.type_name,
                    date=datetime.today().date(),
                )
                db.session.add(new_balancesheet)
        else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
        
        fund = Funds.query.filter_by(fund_name='Bank').first()
        if fund:
            fund.amount += float(amount)
        else:
            return jsonify({'error': f'Missing required field: {field}'}), 400

        try:
            db.session.add(new_bank)
            db.session.commit()
            return jsonify(new_bank.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create fund: {str(e)}'}), 500
        
@app.route('/bankaccounts/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app"])
def get_patch_and_delete_banks_by_id(id):
    session = db.session()
    bank = session.get(BankItem, id)

    if request.method == 'GET':
        if not bank:
            return jsonify({'error': 'Bank not found'}), 404
        return jsonify(bank.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not bank:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400


        for key, value in data.items():
            setattr(bank, key, value)

        try:
            db.session.commit()
            return jsonify(bank.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500
        
@app.route('/funds', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_funds():
    if request.method == 'GET':  
            date = request.args.get('fund_name')  # Corrected syntax
            if date:
                # Assuming your Store model has a date field named 'date'
                funds = Funds.query.filter(Funds.fund_name.ilike(f'%{fund_name}%')).all()
            else:
                funds= Funds.query.all()
            return jsonify([bank.to_dict() for bank in funds]), 201

    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        # Input validation
        required_fields = ['fund_name', 'amount']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        

        fund_name = data.get('fund_name')
        amount = data.get('amount')
        currency = data.get('currency')

        new_fund = Funds(
            fund_name = fund_name,
            amount = amount,
            currency=currency
        )

        try:
            db.session.add(new_fund)
            db.session.commit()
            return jsonify(new_fund.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create fund: {str(e)}'}), 500
        

@app.route('/deposits', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_deposit():
    if request.method == 'GET':  
            date = request.args.get('bakn_name')  # Corrected syntax
            if date:
                # Assuming your Store model has a date field named 'date'
                funds = Deposit.query.filter(Deposit.bank_name.ilike(f'%{bank_name}%')).all()
            else:
                funds= Deposit.query.all()
            return jsonify([bank.to_dict() for bank in funds]), 201

    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        # Input validation
        required_fields = ['bank_name', 'amount']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        

        bank_name = data.get('fund_name')
        bank_details = data.get('bank_details')
        amount = data.get('amount')
        currency = data.get('currency')
        deposit_from = data.get('deposit_from')
        bank_charges = data.get('bank_charges')

        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        new_deposit = Deposit(
            bank_name = bank_name,
            bank_details = bank_details,
            amount = amount,
            currency=currency,
            deposit_from=deposit_from,
            date = date,
            bank_charges = bank_charges,
        )

        fund = Funds.query.filter_by(fund_name=deposit_from).first()
        if fund:
            fund.amount += float(amount)
        else:
            return jsonify({'error': 'Fund not availbale'}), 400
        
        # Update Cash at Bank
        bank_account = AccountCategory.query.filter_by(category_name='Cash at Bank').first()
        if bank_account:
                bank_account.amount += float(amount)
                cash_bank = float(amount) * -1
                new_balancesheet = BalanceSheet(
                    account_type_id=bank_account.account_type_id,
                    category_name='Cash at Bank',
                    amount=cash_bank,
                    type_name=bank_account.type_name,
                    date=date,
                )
                db.session.add(new_balancesheet)
        else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
        
        # Update Cash at Hand
        bank_account = AccountCategory.query.filter_by(category_name='Cash at Hand').first()
        if bank_account:
                bank_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=bank_account.account_type_id,
                    category_name='Cash at Hand',
                    amount=float(amount),
                    type_name=bank_account.type_name,
                    date=date,
                )
                db.session.add(new_balancesheet)
        else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
        
        try:
            db.session.add(new_deposit)
            db.session.commit()
            return jsonify(new_deposit.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Deposit: {str(e)}'}), 500
        
@app.route('/sparecategories', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_vehicle_spare_categories():
    if request.method == 'GET':  
            date = request.args.get('oil_name')  # Corrected syntax
            if date:
                # Assuming your Store model has a date field named 'date'
                spares = SpareCategory.query.filter(SpareCategory.spare_category_name.ilike(f'%{spare_category_name}%')).all()
            else:
                spares = SpareCategory.query.all()
            return jsonify([spare.to_dict() for spare in spares]), 201

    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        # Input validation
        required_fields = ['spare_category_name']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        

        spare_category_name = data.get('spare_category_name')

        new_spare_category = SpareCategory(
            spare_category_name = spare_category_name,
        )
        
        try:
            db.session.add(new_spare_category)
            db.session.commit()
            return jsonify(new_spare_category.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create SpareCategory: {str(e)}'}), 500

@app.route('/sparesubcategories', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_vehicle_spare_sub_categories():
    if request.method == 'GET':  
        spare_subcategory_name = request.args.get('spare_subcategory_name')  # Corrected variable
        if spare_subcategory_name:
            spares = SpareSubCategory.query.filter(SpareSubCategory.spare_subcategory_name.ilike(f'%{spare_subcategory_name}%')).all()
        else:
            spares = SpareSubCategory.query.all()
        return jsonify([spare.to_dict() for spare in spares]), 200

    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for creation'}), 400
        
        items_data = data.get('items')
        
        # Validate input and create objects
        spare_objects = []
        for item_data in items_data:
            required_fields = ['spare_subcategory_name', 'price', 'quantity', 'measurement', 'date']
            for field in required_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400

            # Extract and process data
            spare_subcategory_name = item_data['spare_subcategory_name']
            price = item_data['price']
            quantity = item_data['quantity']
            measurement = item_data['measurement']
            date_str = item_data['date']
            try:
                date = datetime.strptime(date_str, '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': f'Invalid date format for item: {spare_subcategory_name}'}), 400
            
            spareitem = SpareSubCategory.query.filter_by(spare_subcategory_name=spare_subcategory_name, measurement=measurement).first()
            if spareitem:
                spareitem.quantity += float(quantity)
            else:
                # Create SpareSubCategory object
                spare_object = SpareSubCategory(
                    spare_subcategory_name=spare_subcategory_name,
                    quantity=quantity,
                    date=date,
                    price=price,
                    measurement=measurement,
                )
                spare_objects.append(spare_object)
        
        try:
            # Bulk save all objects
            db.session.bulk_save_objects(spare_objects)
            db.session.commit()
            return jsonify({'message': f'{len(spare_objects)} spare parts added successfully'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to save spare parts: {str(e)}'}), 500

@app.route('/sparesubcategories/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_spare_items_by_id(id):

    tyre = SpareSubCategory.query.filter_by(id=id).first()

    if request.method == 'GET':
        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(tyre.to_dict()), 200
    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400


        for key, value in data.items():
            setattr(tyre, key, value)

        try:
            db.session.commit()
            return jsonify(tyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500
        
    elif request.method == 'DELETE':
        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        
        try:
            db.session.delete(tyre)
            db.session.commit()
            return jsonify({'message': 'Stock deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete tyre: {str(e)}'}), 500

        
@app.route('/pumpnames', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post__fuel_pump_names():
    if request.method == 'GET':  
            spares = PumpName.query.all()
            return jsonify([spare.to_dict() for spare in spares]), 201

    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        # Input validation
        required_fields = ['pump_name','initial_reading','date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        

        pump_name = data.get('pump_name')
        litres = data.get('litres')
        initial_reading = data.get('initial_reading')
        reading = data.get('reading')
        pump_location = data.get('pump_location')
        fuel_type = data.get('fuel_type')

        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        new_fuel_pump = PumpName(
            pump_name = pump_name,
            pump_location = pump_location,
            litres = litres,
            initial_reading = initial_reading,
            reading=reading,
            fuel_type=fuel_type,
            date=date,
        )
        
        try:
            db.session.add(new_fuel_pump)
            db.session.commit()
            return jsonify(new_fuel_pump.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Deposit: {str(e)}'}), 500
        
@app.route('/pumpnames/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_pumps_by_id(id):
    
    pump = PumpName.query.filter_by(id=id).first()

    if request.method == 'GET':
        if not pump:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(pump.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not pump:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

        for key, value in data.items():
            setattr(pump, key, value)

        try:
            db.session.commit()
            return jsonify(pump.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update truck: {str(e)}'}), 500

    elif request.method == 'DELETE':
        if not pump:
            return jsonify({'error': 'Item not found'}), 404
        
        try:
            db.session.delete(pump)
            db.session.commit()
            return jsonify({'message': 'Truck deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete truck: {str(e)}'}), 500
        
        
@app.route('/pumpfuelings', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_pump_fuelings():
    if request.method == 'GET':  
            spares = PumpFueling.query.all()
            return jsonify([spare.to_dict() for spare in spares]), 201

    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        # Input validation
        required_fields = ['pump_name','reading','date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        pump_name = data.get('pump_name')
        truck_number = data.get('truck_number')
        litres = data.get('litres')
        reading = data.get('reading')
        price = data.get('price')
        order = data.get('order')
        pump_location = data.get('pump_location')


        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        truck = Truck.query.filter_by(truck_number=truck_number).first()
        if not truck:
            return jsonify({'error': f'Missing: {truck}'}), 400
        
        pump = PumpName.query.filter_by(pump_name=pump_name).first()
        if not pump:
            return jsonify({'error': f'Missing: {pump}'}), 400

        new_pump_fueling = PumpFueling(
            pump_id=pump.id,
            truck_id=truck.id,
            pump_location = pump_location,
            pump_name = pump_name,
            litres = litres,
            reading = reading,
            truck_number=truck_number,
            price=price,
            order=order,
            date=date,
        )

        pump = PumpName.query.filter_by(pump_name=pump_name).first()
        if pump:
            pump.litres -= float(litres)
            pump.reading += float(litres)
        
        try:
            db.session.add(new_pump_fueling)
            db.session.commit()
            return jsonify(new_pump_fueling.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Deposit: {str(e)}'}), 500
        

@app.route('/pumpfuelings/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_pumpfuelings_by_id(id):
    
    pump = PumpFueling.query.filter_by(id=id).first()

    if request.method == 'GET':
        if not pump:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(pump.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not pump:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

        for key, value in data.items():
            setattr(pump, key, value)

        try:
            db.session.commit()
            return jsonify(pump.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update truck: {str(e)}'}), 500

    elif request.method == 'DELETE':
        if not pump:
            return jsonify({'error': 'Item not found'}), 404
        
        try:
            db.session.delete(pump)
            db.session.commit()
            return jsonify({'message': 'Truck deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete truck: {str(e)}'}), 500
        
        
@app.route('/pumpupdates', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_pump_updates():
    if request.method == 'GET':  
            spares = PumpUpdate.query.all()
            return jsonify([spare.to_dict() for spare in spares]), 201

    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        # Input validation
        required_fields = ['pump_name','reading','date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        pump_name = data.get('pump_name')
        litres = data.get('litres')
        reading = data.get('reading')

        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        
        pump = PumpName.query.filter_by(pump_name=pump_name).first()
        if not pump:
            return jsonify({'error': f'Missing: {pump}'}), 400

        new_pump_update = PumpUpdate(
            pump_id=pump.id,
            pump_name = pump_name,
            litres = litres,
            reading = reading,
            date=date,
        )

        pump = PumpName.query.filter_by(pump_name=pump_name).first()
        if pump:
            pump.litres += float(litres)
        
        try:
            db.session.add(new_pump_update)
            db.session.commit()
            return jsonify(new_pump_update.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Deposit: {str(e)}'}), 500
        
@app.route('/retreadshoptrips', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_retreadshop_trips():
    if request.method == 'GET':
        trips = RetreadTyreTrip.query.all()
        return jsonify([trip.to_dict() for trip in trips]), 200
    
    elif request.method == "POST":
        data = request.json

        # Handle the invoice details
        required_invoice_fields = ['vendor_name', 'vendor_email', 'currency', 'vendor_pin', 'date']
        for field in required_invoice_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        vendor_name = data.get('vendor_name')
        vendor_email = data.get('vendor_email')
        vendor_phone = data.get('vendor_phone')
        currency = data.get('currency')
        vendor_pin = data.get('vendor_pin')
        trip_number = data.get('trip_number')

        
        # Convert date string to Python date object
        date_str = data.get('date')
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

        # Create the new invoice
        new_trip = RetreadTyreTrip(
            vendor_name=vendor_name,
            vendor_email=vendor_email,
            currency=currency,
            vendor_phone=vendor_phone,
            vendor_pin=vendor_pin,
            trip_number=trip_number,
            date=date,
        )

        # Handle the items
        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the invoice'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'size', 'serial_number']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400
            
            item_details = item_data.get('item_details')
            size = item_data.get('size')
            serial_number = item_data.get('serial_number')
            tyre_mileage = item_data.get('tyre_mileage')

            # Create a new invoice item
            new_item = RetreadTyreTripItem(
                item_details=item_details,
                size=size,
                serial_number=serial_number,
                tyre_mileage=tyre_mileage,
            )
            
            # Append the item to the invoice
            new_trip.items.append(new_item)
            
            # Create a new pump update
            new_pump_update = ShopRetread(
                item_details=item_details,
                serial_number=serial_number,
                size=size,
                tyre_mileage=tyre_mileage,
                position='SHOP',
                date=date,
            )
            db.session.add(new_pump_update)

        try:
            db.session.add(new_trip)
            db.session.commit()
            return jsonify(new_trip.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Trip: {str(e)}'}), 500

        
@app.route('/shopretreads', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_shop_retreads():
    if request.method == 'GET':  
            spares = ShopRetread.query.all()
            return jsonify([spare.to_dict() for spare in spares]), 201

    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        # Input validation
        required_fields = ['item_details','serial_number','size']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        item_details = data.get('item_details')
        serial_number = data.get('serial_number')
        size = data.get('size')
        tyre_mileage = data.get('tyre_mileage')
        position = data.get('position')
        date = data.get('date')

        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        new_pump_update = ShopRetread(
            item_details=item_details,
            serial_number=serial_number,
            size=size,
            tyre_mileage=tyre_mileage,
            position=position,
            date=date,
        )
        
        try:
            db.session.add(new_pump_update)
            db.session.commit()
            return jsonify(new_pump_update.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Deposit: {str(e)}'}), 500

@app.route('/shopretreads/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app","http://localhost:4000"])
def get_patch_and_delete_shop_retread_by_id(id):
    tyre = ShopRetread.query.filter_by(id=id).first()

    if request.method == 'GET':
        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(tyre.to_dict()), 200

    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 400

        if not tyre:
            return jsonify({'error': 'Item not found'}), 404

        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400

        # Update the tyre object with the new data
        for key, value in data.items():
            setattr(tyre, key, value)

        try:
            db.session.commit()
            return jsonify(tyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update tyre: {str(e)}'}), 500

    elif request.method == 'DELETE':
        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        
        try:
            db.session.delete(tyre)
            db.session.commit()
            return jsonify({'message': 'Tyre deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete tyre: {str(e)}'}), 500

        
@app.route('/vehiclemantainances', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_vehicle_mantainaces():
    if request.method == 'GET':
        trips = VehicleMantainance.query.all()
        return jsonify([trip.to_dict() for trip in trips]), 200
    
    elif request.method == "POST":
        data = request.json

        # Handle required fields for the trip
        required_fields = ['truck_number', 'vehicle_type', 'job_description', 'manufacturer', 'items']
        for field in required_fields:
            if field not in data:
                logging.warning(f"Missing required field: {field}")
                return jsonify({'error': f'Missing required field: {field}'}), 400

        truck_number = data.get('truck_number')
        vehicle_type = data.get('vehicle_type')
        job_description = data.get('job_description')
        manufacturer = data.get('manufacturer')
        repair_number = data.get('repair_number')
        
        # Convert date string to Python date object
        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        truck = Truck.query.filter_by(truck_number=truck_number).first()
        if not truck:
            return jsonify({'error': 'Truck not found'}), 404

        # Create the new trip
        new_trip = VehicleMantainance(
            truck_id = truck.id,
            truck_number = truck_number,
            vehicle_type = vehicle_type,
            date = date,
            job_description = job_description,
            manufacturer = manufacturer,
            repair_number = repair_number,
        )

        items_data = data.get('items')
        if not items_data:
            logging.warning("Invalid or missing items; expected a non-empty list")
            return jsonify({'error': 'No items provided for the invoice'}), 400

        for item_data in items_data:
            required_item_fields = ['spare_subcategory_name','quantity', 'mechanic', 'job_name', 'position']
            for field in required_item_fields:
                if field not in item_data:
                    logging.warning(f"Missing required field in item: {field}")
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400
            
            spare_subcategory_name = item_data.get('spare_subcategory_name')
            spare_category_name = item_data.get('spare_category_name')
            quantity = item_data.get('quantity')
            mechanic = item_data.get('mechanic')
            job_name = item_data.get('job_name')
            position = item_data.get('position')
            price = item_data.get('price')

            # Create a new invoice item
            new_item = VehicleMaintananceItem(
                spare_subcategory_name = spare_subcategory_name,
                spare_category_name = spare_category_name,
                quantity = quantity,
                mechanic = mechanic,
                job_name = job_name,
                position = position,
                price = price,
            )

            spare = SpareSubCategory.query.filter_by(spare_subcategory_name=spare_subcategory_name).first()
            if spare:
                spare.quantity -= float(quantity)
            
            # Append the item to the invoice
            new_trip.items.append(new_item)

        try:
            db.session.add(new_trip)
            db.session.commit()
            return jsonify(new_trip.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Trip: {str(e)}'}), 500


@app.route('/stockitems', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_stockitems():
    if request.method == 'GET':
        item_details = request.args.get('item_details')

        stocks = StockItem.query.all()
            
        return jsonify([stock.to_dict() for stock in stocks]), 200

    elif request.method == 'POST':
        data = request.json
        print("Received data:", data)

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400
        
        required_fields = ['item_details', 'quantity']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        item_details = data.get('item_details')
        quantity = data.get('quantity')
        price = data.get('price')
        store = data.get('store')

        new_stock = StockItem(
            item_details=item_details,
            quantity=quantity,
            price=price,
            store=store
        )
        try:
            db.session.add(new_stock)
            db.session.commit()
            return jsonify(new_stock.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            print("Error:", str(e))
            return jsonify({'error': f'Failed to create stock: {str(e)}'}), 500
        
@app.route('/stockitems/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_patch_and_delete_stock_items_by_id(id):
    tyre = StockItem.query.get(id)

    if request.method == 'GET':
        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        return jsonify(tyre.to_dict()), 200
    elif request.method == 'PATCH':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for update'}), 401

        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        
        if 'date' in data:
            try:
                # Parse the date string into a datetime object
                data['date'] = datetime.strptime(data['date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Date must be in YYYY-MM-DD format'}), 400


        for key, value in data.items():
            setattr(tyre, key, value)

        try:
            db.session.commit()
            return jsonify(tyre.to_dict()), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update item: {str(e)}'}), 500
        
    elif request.method == 'DELETE':
        if not tyre:
            return jsonify({'error': 'Item not found'}), 404
        
        try:
            db.session.delete(tyre)
            db.session.commit()
            return jsonify({'message': 'Stock deleted successfully'}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to delete tyre: {str(e)}'}), 500

@app.route('/stockitembulk', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_alot_spares():
    if request.method == 'GET':
        item_details = request.args.get('item_details')

        stocks = StockItem.query.all()
            
        return jsonify([stock.to_dict() for stock in stocks]), 200

    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for creation'}), 400
        
        items_data = data.get('items')
        
        # Validate input and create objects
        stock_objects = []
        for item_data in items_data:
            required_fields = ['item_details', 'price', 'quantity', 'measurement', 'store']
            for field in required_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field: {field}'}), 400

            # Extract and process data
            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            price = item_data.get('price')
            store = item_data.get('store')
            measurement = item_data.get('measurement')

            stockitem = StockItem.query.filter_by(item_details=item_details, measurement=measurement).first()
            if not stockitem:
                # Create SpareSubCategory object
                spare_object = StockItem(
                    item_details=item_details,
                    quantity=quantity,
                    price=price,
                    store=store,
                    measurement=measurement,
                )
                stock_objects.append(spare_object)
            else:
                stockitem.quantity += quantity
                
        
        try:
            # Bulk save all objects
            db.session.bulk_save_objects(stock_objects)
            db.session.commit()
            return jsonify({'message': f'{len(stock_objects)} spare parts added successfully'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to save spare parts: {str(e)}'}), 500
        
@app.route('/creditnotes', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app", "http://localhost:4000"])
def get_and_post_credit_notes():
    if request.method == 'GET':

        invoices = CreditNote.query.all()
        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['customer_name', 'credit_number', 'credit_date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        customer_name = data.get('customer_name')
        credit_number = data.get('credit_number')
        category_name = data.get('category_name')
        customer_phone = data.get('customer_phone')
        customer_email = data.get('customer_email')
        type_vat=data.get('type_vat')
        vendor_pin=data.get('vendor_pin')

        date_str = data.get('credit_date')
        credit_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        
        customer = Customer.query.filter_by(customer_name=customer_name).first()
        if not customer:
            return jsonify({'error': f'customer with name {customer_name} does not exist'}), 400
        
        account = AccountCategory.query.filter_by(category_name=category_name).first()
        if not account:
             return jsonify({'error': f'Customer with name {category_name} does not exist'}), 400

        new_credit_note = CreditNote(
            customer_id = customer.id,
            category_id=account.id,
            category_name=category_name,
            customer_name =customer_name,
            customer_phone = customer_phone,
            customer_email = customer_email,
            vendor_pin = vendor_pin,
            credit_number=credit_number,
            credit_date=credit_date,
            type_vat=type_vat,
        )

        items_data = data.get('items')
        if not items_data:
            return jsonify({'error': 'No items provided for the bill'}), 400

        for item_data in items_data:
            required_item_fields = ['item_details', 'quantity', 'rate', 'vat', 'rate_vat', 'amount']
            for field in required_item_fields:
                if field not in item_data:
                    return jsonify({'error': f'Missing required field in item: {field}'}), 400

            item_details = item_data.get('item_details')
            quantity = item_data.get('quantity')
            rate = item_data.get('rate')
            vat = item_data.get('vat')
            rate_vat = item_data.get('rate_vat')
            amount = item_data.get('amount')
            sub_total = item_data.get('sub_total')
            measurement=data.get('measurement')

            
            new_credit_note_item = CreditNoteItem(
                item_details=item_details,
                quantity=quantity,
                rate=rate,
                sub_total=sub_total,
                vat=vat,
                rate_vat=rate_vat,
                amount=amount,
                measurement=measurement,
            )

            new_credit_note.items.append(new_credit_note_item)


             # **Highlighted Section**
            stock = StockItem.query.filter_by(item_details=item_details).first()
            if not stock:
                # Create new Total entry if account_name does not exist
                new_stock = StockItem(
                    item_details=item_details,
                    quantity=quantity,
                    price=rate,
                )
                db.session.add(new_stock)
            else:
                # Update existing Total entry
                stock.quantity += float(quantity)

            customer = Customer.query.filter_by(customer_name=customer_name).first()
            if customer:
                customer.total_amount_owed -= amount
            else:
                return jsonify({'error': f'Customer Does Not Exist'}), 400

            # Update Creditors
            creditor_account = AccountCategory.query.filter_by(category_name='Creditors').first()
            if creditor_account:
                creditor_account.amount += float(amount)
                new_balancesheet = BalanceSheet(
                    account_type_id=creditor_account.account_type_id,
                    category_name='Creditors',
                    amount=float(amount),
                    type_name=creditor_account.type_name,
                    date=credit_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Creditors Account category does not exist'}), 400
            
            # Update Stock
            stock_account = AccountCategory.query.filter_by(category_name='Stock').first()
            if stock_account:
                stock_amount = float(stock.price) * float(quantity)
                new_balancesheet = BalanceSheet(
                    account_type_id=stock_account.account_type_id,
                    category_name='Stock',
                    amount=stock_amount,
                    type_name=stock_account.type_name,
                    date=credit_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Stock Account category does not exist'}), 400
            
            # Update Debtors
            debtor_account = AccountCategory.query.filter_by(category_name='Debtors').first()
            if debtor_account:
                debtor_account.amount -= float(amount)
                amount_ = float(amount) * -1
                new_balancesheet = BalanceSheet(
                    account_type_id=debtor_account.account_type_id,
                    category_name='Debtors',
                    amount=amount_,
                    type_name=debtor_account.type_name,
                    date=credit_date,
                )
                db.session.add(new_balancesheet)
            else:
                return jsonify({'error': 'Debtors Account category does not exist'}), 400
            
            # Update Return Inwards
            return_inwards_account = AccountCategory.query.filter_by(category_name='Return Inwards').first()
            if return_inwards_account:
                return_inwards_account.amount -= float(amount)
                new_profit_loss_debtors = TradingProfitLossAccount(
                    account_type_id=return_inwards_account.account_type_id,
                    category_name='Return Inwards',
                    amount=float(amount),
                    type_name=return_inwards_account.type_name,
                    date=credit_date,
                )
                db.session.add(new_profit_loss_debtors)
            else:
                return jsonify({'error': 'Return Inwards Account category does not exist'}), 400

        try:
            db.session.add(new_credit_note)
            db.session.commit()
            return jsonify(new_credit_note.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Credit Note: {str(e)}'}), 500

@app.route('/tradingprofitandlossaccounts', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app"])
def get_and_post_profit_loss_account():
    if request.method == 'GET':

        invoices = TradingProfitLossAccount.query.all()
        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['amount', 'category_name']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        category_name = data.get('category_name')
        amount = data.get('amount')
        type_name = data.get('type_name')

        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
        
        account = AccountType.query.filter_by(type_name=type_name).first()
        if not account:
             return jsonify({'error': f'Customer with name {type_name} does not exist'}), 400

        new_profit_loss_debtors = TradingProfitLossAccount(
            account_type_id = account.id,
            category_name=category_name,
            amount = amount,
            type_name=type_name,
            date = date,
        )

        try:
            db.session.add(new_profit_loss_debtors)
            db.session.commit()
            return jsonify(new_profit_loss_debtors.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Credit Note: {str(e)}'}), 500
        
@app.route('/balancesheets', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app"])
def get_and_post_balance_sheet_account():
    if request.method == 'GET':

        invoices = BalanceSheet.query.all()
        return jsonify([invoice.to_dict() for invoice in invoices]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['category_name', 'amount', 'type_name']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        category_name = data.get('category_name')
        amount = data.get('amount')
        type_name = data.get('type_name')

        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
        
        account = AccountType.query.filter_by(type_name=type_name).first()
        if not account:
             return jsonify({'error': f'Customer with name {type_name} does not exist'}), 400

        new_balancesheet = BalanceSheet(
            account_type_id = account.id,
            category_name=category_name,
            amount = amount,
            type_name=type_name,
            date = date,
        )

        try:
            db.session.add(new_balancesheet)
            db.session.commit()
            return jsonify(new_balancesheet.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create BalanceSheet: {str(e)}'}), 500

@app.route('/cashbooks', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app"])
def get_and_post_cash_books():
    if request.method == 'GET':

        cashbooks = CashBook.query.all()
        return jsonify([cashbook.to_dict() for cashbook in cashbooks]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['item_details', 'bank', 'date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        item_details = data.get('item_details')
        bank = data.get('bank')
        bank_amount = data.get('bank_amount')
        cash_amount = data.get('cash_amount')

        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        new_cashbook = CashBook(
            item_details = item_details.id,
            bank_amount=bank_amount,
            bank = bank,
            cash_amount=cash_amount,
            date = date,
        )

        try:
            db.session.add(new_cashbook)
            db.session.commit()
            return jsonify(new_cashbook.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create CashBook: {str(e)}'}), 500
        
@app.route('/cashbookdebits', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app"])
def get_and_post_cash_book_debits():
    if request.method == 'GET':

        cashbooks = CashBookDebit.query.all()
        return jsonify([cashbook.to_dict() for cashbook in cashbooks]), 200
    
    elif request.method == "POST":
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['item_details', 'bank', 'date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        item_details = data.get('item_details')
        bank = data.get('bank')
        bank_amount = data.get('bank_amount')
        cash_amount = data.get('cash_amount')

        date_str = data.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        new_cashbookdebit = CashBookDebit(
            item_details = item_details.id,
            bank_amount=bank_amount,
            bank = bank,
            cash_amount=cash_amount,
            date = date,
        )

        try:
            db.session.add(new_cashbookdebit)
            db.session.commit()
            return jsonify(new_cashbookdebit.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create CashBookDebit: {str(e)}'}), 500
        
@app.route('/expenses', methods=['GET', 'POST'])
@jwt_required()
@cross_origin(supports_credentials=True, origins=["https://demoobooks.netlify.app"])
def get_and_post_expenses():
    if request.method == 'GET':
        expenses = Expense.query.all()
        return jsonify([expense.to_dict() for expense in expenses]), 200
    
    if request.method == 'POST':
        data = request.json

        if not data:
            return jsonify({'error': 'No data provided for create'}), 400

        required_fields = ['expense_amount', 'expense_name']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
            
        expense_name = data.get('expense_name')
        expense_amount = data.get('expense_amount')

        new_expense = Expense(
            expense_name=expense_name,
            expense_amount=expense_amount,
        )

        try:
            db.session.add(new_expense)
            db.session.commit()
            return jsonify(new_expense.to_dict()), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to create Expense: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(port=1718, debug=True)
