from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy_serializer import SerializerMixin
from werkzeug.security import generate_password_hash, check_password_hash
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from marshmallow import fields
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    email = db.Column(db.String, nullable=False, unique=True)
    phone_number = db.Column(db.String,nullable=False)
    password = db.Column(db.String, nullable=False)

    @validates('password')
    def validate_password(self, key, password):
        if len(password) < 8:
            raise ValueError('Password must be more than 8 characters.')
        return password

    @validates('email')
    def validate_email(self, key, email):
        if not email.endswith("@gmail.com"):
            raise ValueError("Email is not valid. It should end with @gmail.com")
        return email

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def to_dict(self):
        return {
            "id":self.id,
            "username":self.username,
            "phone_number":self.phone_number,
            'email':self.email,
        }

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}')>"

class RevokedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), unique=True, nullable=False)  # JWT ID
    revoked_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f"<User(id={self.id}')>"

class Purchase(db.Model, SerializerMixin):
    __tablename__ = 'purchases'

    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String)
    description = db.Column(db.String)
    quantity = db.Column(db.Integer)
    email = db.Column(db.String)
    vat = db.Column(db.String)
    supplier_name = db.Column(db.String)
    supplier_pin = db.Column(db.String)
    credit = db.Column(db.String)
    price = db.Column(db.Integer)
    terms = db.Column(db.String)
    date = db.Column(db.Date)

    def __repr__(self):
        return f"<Purchase id={self.id}, name={self.name}, description={self.description}, quantity={self.quantity}, email={self.email}, vat={self.vat}, supplier_name={self.supplier_name}, supplier_pin={self.supplier_pin}, credit={self.credit}, terms={self.terms},date={self.date}>"

class Store(db.Model, SerializerMixin):
    __tablename__ = 'stores'

    id = db.Column(db.Integer, primary_key=True)
    item_details = db.Column(db.String)
    truck_number = db.Column(db.String)
    quantity = db.Column(db.Integer)
    mechanic = db.Column(db.String)
    date = db.Column(db.Date)
    spare_category = db.Column(db.String)
    price = db.Column(db.Float)
    description = db.Column(db.String)
    truck_id = db.Column(db.Integer, db.ForeignKey('trucks.id'))

    def to_dict(self):
        return {
            'id': self.id,
            'item_details': self.item_details,
            'truck_number': self.truck_number,
            'quantity': self.quantity,
            'mechanic': self.mechanic,
            'date': self.date,
            'spare_category': self.spare_category,
            'description': self.description,
            'price': self.price,
            'truck_id': self.truck_id
        }

    def __repr__(self):
        return f"<Store id={self.id}, item_details={self.item_details}, truck_number={self.truck_number}, quantity={self.quantity}, mechanic={self.mechanic}, date={self.date}>"
    
class Item(db.Model, SerializerMixin):
    __tablename__ = 'items'
      
    id = db.Column(db.Integer, primary_key = True)
    item_details = db.Column(db.String)
    quantity = db.Column(db.Integer)
    price = db.Column(db.Float)
    

    def __repr__(self):
        return f"<Item id={self.id}, name={self.item_details}, quantity={self.quantity}>"
    
class Update(db.Model, SerializerMixin):
    __tablename__ = 'updates'

    id = db.Column(db.Integer, primary_key = True)
    item_details = db.Column(db.String)
    quantity = db.Column(db.Integer)
    date = db.Column(db.Date)

    def __repr__(self):
        return f"<Update id={self.id},item_details={self.item_details}, quantity={self.quantity}, date={self.date}>"



class Tyre(db.Model, SerializerMixin):
    __tablename__ = 'tyres'

    id = db.Column(db.Integer, primary_key = True)
    item_details = db.Column(db.String)
    quantity = db.Column(db.Integer)
    size = db.Column(db.String)
    price = db.Column(db.Float)

    def to_dict(self):
        return {
            'id': self.id,
            'item_details': self.item_details,
            'quantity': self.quantity,
            'size': self.size,
            'price': self.price,
        }

    def __repr__(self):
        return f"<Tyre id={self.id}, name={self.item_details}, size={self.size}, quantity={self.quantity}>"
    
class Removetyre(db.Model, SerializerMixin):
    __tablename__ = 'removetyres'

    id = db.Column(db.Integer, primary_key=True)
    item_details = db.Column(db.String)
    size = db.Column(db.String)
    truck_number = db.Column(db.String)
    serial_number = db.Column(db.String, unique=True)
    starting_mileage = db.Column(db.Integer)
    position = db.Column(db.String)
    status = db.Column(db.String)
    price = db.Column(db.Float)
    quantity = db.Column(db.Integer)
    date = db.Column(db.Date)
    truck_id = db.Column(db.Integer, db.ForeignKey('trucks.id'))

    def to_dict(self):
        return {
            'id': self.id,
            'item_details': self.item_details,
            'price':self.price,
            'size': self.size,
            'truck_number': self.truck_number,
            'serial_number': self.serial_number,
            'starting_mileage': self.starting_mileage,
            'position': self.position,
            'status': self.status,
            'quantity': self.quantity,
            'date': self.date,
            'truck_id': self.truck_id
        }

    def __repr__(self):
        return f"<Removetyre id={self.id}, item_details={self.item_details}, size={self.size}, truck_number={self.truck_number}, serial_number={self.serial_number}, starting_mileage={self.starting_mileage}, position={self.position}, status={self.status}, quantity={self.quantity}, date={self.date}>"   
    
class RetreadTyre(db.Model, SerializerMixin):
    __tablename__ = 'retreadtyres'

    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String)
    serial_number = db.Column(db.String)
    size = db.Column(db.String)
    status = db.Column(db.String)
    tyre_mileage = db.Column(db.Integer)
    date = db.Column(db.Date)

    def to_dict(self):
            return {
                'id': self.id,
                'name': self.name,
                'serial_number': self.serial_number,
                'size': self.size,
                'status': self.status,
                'tyre_mileage': self.tyre_mileage,
                'date': self.date,
            }

    def __repr__(self):
        return f"<OldTyres id={self.id}, name={self.name},  size={self.size}, serial_number={self.serial_number}, tyre_mileage={self.tyre_mileage}, status={self.status}, date={self.date}>"
class RetreadedTyre(db.Model, SerializerMixin):
    __tablename__ = 'retreadedtyres'

    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String)
    starting_mileage = db.Column(db.Integer, unique=False)
    serial_number = db.Column(db.String, unique=False)
    size = db.Column(db.String)
    truck_number = db.Column(db.String)
    status = db.Column(db.String)
    final_mileage = db.Column(db.Integer)
    tyre_mileage = db.Column(db.Integer)
    position = db.Column(db.String)
    price = db.Column(db.Float)
    date = db.Column(db.Date)

    def __repr__(self):
        return f"<RetreadedTyre id={self.id}, name={self.name},  size={self.size},truck_number={self.truck_number}, serial_number={self.truck_number}, starting_mileage={self.truck_number}, final_mileage={self.final_mileage}, position = {self.position},date={self.date}>"
  

class ShopRetread(db.Model, SerializerMixin):
    __tablename__ = 'shopretreads'

    id = db.Column(db.Integer, primary_key = True)
    item_details = db.Column(db.String)
    serial_number = db.Column(db.String)
    size = db.Column(db.String)
    tyre_mileage = db.Column(db.Integer)
    position = db.Column(db.String)
    date = db.Column(db.Date)

    def to_dict(self):
        return {
            'id': self.id,
            'item_details': self.item_details,
            'size': self.size,
            'serial_number': self.serial_number,
            'tyre_mileage': self.tyre_mileage,
            'position': self.position,
            'date': self.date,
        }

    def __repr__(self):
        return f"<ShopRetread id={self.id}, name={self.item_details},  size={self.size}, position={self.position}, tyre_mileage={self.tyre_mileage}, position = {self.position},date={self.date}>" 
     

class RemoveRetreadtyre(db.Model, SerializerMixin):
    __tablename__ = 'removeretreadtyres'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    size = db.Column(db.String)
    serial_number = db.Column(db.String)
    truck_number = db.Column(db.String)
    starting_mileage = db.Column(db.Integer)
    status = db.Column(db.String)
    position = db.Column(db.String)
    price = db.Column(db.Float)
    date = db.Column(db.Date)
    truck_id = db.Column(db.Integer, db.ForeignKey('trucks.id'))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'size': self.size,
            'serial_number': self.serial_number,
            'truck_number': self.truck_number,
            'starting_mileage': self.starting_mileage,
            'status': self.status,
            'position': self.position,
            'price': self.price,
            'date': self.date,
            'truck_id': self.truck_id
        }

    def __repr__(self):
        return f"<RemoveRetreadtyre id={self.id}, name={self.name}, size={self.size}, truck_number={self.truck_number}, serial_number={self.serial_number}, starting_mileage={self.starting_mileage}, status={self.status}, position={self.position}, date={self.date}>"


class UnfitRetreadtyre(db.Model, SerializerMixin):
    __tablename__ = 'unfitremoveretreadtyres'

    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String)
    size = db.Column(db.String)
    truck_number = db.Column(db.String)
    serial_number = db.Column(db.String)
    starting_mileage = db.Column(db.Integer)
    position = db.Column(db.String)
    reason = db.Column(db.String)
    final_mileage = db.Column(db.Integer)
    tyre_mileage = db.Column(db.Integer)
    date = db.Column(db.Date)


    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'size': self.size,
            'serial_number': self.serial_number,
            'truck_number': self.truck_number,
            'starting_mileage': self.starting_mileage,
            'position': self.position,
            'reason':self.reason,
            'final_mileage':self.final_mileage,
            'tyre_mileage':self.tyre_mileage,
            'date': self.date,
        }

    def __repr__(self):
        return f"<UnfitRetreadtyre id={self.id}, name={self.name}, type={self.type}, quantity={self.quantity}, truck_number={self.truck_number}, serial_number={self.truck_number}, starting_mileage={self.truck_number},date={self.date}>"
    
class RetreadTyreupdate(db.Model, SerializerMixin):
    __tablename__ = 'retreadtyreupdates'

    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String)
    size = db.Column(db.String)
    serial_number = db.Column(db.String,unique=True)
    quantity = db.Column(db.Integer)
    date = db.Column(db.Date)

    def __repr__(self):
        return f"<Tyreupdate id={self.id}, name={self.name}, type={self.type}, quantity={self.quantity}, date={self.date}>"    
    
class OldTyres(db.Model, SerializerMixin):
    __tablename__ = 'oldtyres'

    id = db.Column(db.Integer, primary_key = True)
    item_details = db.Column(db.String)
    serial_number = db.Column(db.String, unique=True)
    starting_mileage = db.Column(db.Integer)
    size = db.Column(db.String)
    retread_counter = db.Column(db.Float)
    reason = db.Column(db.String)
    truck_number = db.Column(db.String)
    status = db.Column(db.String)
    condition = db.Column(db.String)
    retread_status = db.Column(db.String)
    final_mileage = db.Column(db.Integer)
    tyre_mileage = db.Column(db.Integer)
    position = db.Column(db.String)
    date = db.Column(db.Date)
    truck_id = db.Column(db.Integer, db.ForeignKey('trucks.id'))

    def to_dict(self):
        return {
            'id': self.id,
            'item_details': self.item_details,
            'serial_number': self.serial_number,
            'starting_mileage': self.starting_mileage,
            'size': self.size,
            'retread_counter': self.retread_counter,
            'retread_status': self.retread_status,
            'reason': self.reason,
            'truck_number': self.truck_number,
            'final_mileage': self.final_mileage,
            'tyre_mileage': self.tyre_mileage,
            'position': self.position,
            'date': self.date,
            'truck_id': self.truck_id,
            'status': self.status,
            'condition': self.condition,
        }

    def __repr__(self):
        return f"<OldTyres id={self.id}, name={self.item_details},  size={self.size},truck_number={self.truck_number}, serial_number={self.truck_number}, starting_mileage={self.truck_number}, final_mileage={self.final_mileage}, position = {self.position},date={self.date}>"
    
class FitUsedTyre(db.Model, SerializerMixin):
    __tablename__ = 'fitusedtyres'

    id = db.Column(db.Integer, primary_key = True)
    item_details = db.Column(db.String)
    size = db.Column(db.String)
    serial_number = db.Column(db.String)
    truck_number = db.Column(db.String)
    starting_mileage = db.Column(db.Integer)
    status = db.Column(db.String)
    position = db.Column(db.String)
    date = db.Column(db.Date)
    truck_id = db.Column(db.Integer, db.ForeignKey('trucks.id'))

    def to_dict(self):
        return {
            'id': self.id,
            'item_details': self.item_details,
            'size': self.size,
            'serial_number': self.serial_number,
            'truck_number': self.truck_number,
            'starting_mileage': self.starting_mileage,
            'status': self.status,
            'position': self.position,
            'date': self.date,
            'truck_id': self.truck_id
        }

    def __repr__(self):
        return f"<FitUsedTyre id={self.id}, name={self.item_details},  size={self.size},truck_number={self.truck_number}, serial_number={self.truck_number}, starting_mileage={self.truck_number}, final_mileage={self.final_mileage}, position = {self.position},date={self.date}>"
    
class Truck(db.Model, SerializerMixin):
    __tablename__ = 'trucks'

    id = db.Column(db.Integer, primary_key=True)
    truck_number = db.Column(db.String, unique=True, nullable=False)
    driver = db.Column(db.String, nullable=False)
    vehicle_type = db.Column(db.String)
    manufacturer = db.Column(db.String)
    vehicle_id = db.Column(db.Integer)
    trailer = db.Column(db.String)
    contact = db.Column(db.String)
    
    removetyres = db.relationship('Removetyre', backref='truck', cascade="all, delete-orphan", lazy=True)
    oldtyres = db.relationship('OldTyres', backref='truck', cascade="all, delete-orphan", lazy=True)
    removeretreadtyres = db.relationship('RemoveRetreadtyre', backref='truck', cascade="all, delete-orphan", lazy=True)
    stores = db.relationship('Store', backref='truck', cascade="all, delete-orphan", lazy=True)
    mantainances = db.relationship('VehicleMantainance', backref='truck', cascade="all, delete-orphan", lazy=True)
    fueling = db.relationship('PumpFueling', backref='truck', cascade="all, delete-orphan", lazy=True)
    invoices = db.relationship('NewInvoiceItem', backref='truck', cascade="all, delete-orphan", lazy=True)
    bills = db.relationship('NewBillItem', backref='truck', cascade="all, delete-orphan", lazy=True)
    used_tyres = db.relationship('FitUsedTyre', backref='truck', cascade="all, delete-orphan", lazy=True)


    def to_dict(self):
        return {
            "id": self.id,
            "truck_number": self.truck_number,
            "driver": self.driver,
            'trailer':self.trailer,
            "vehicle_type": self.vehicle_type,
            'contact':self.contact,
            "vehicle_id":self.vehicle_id,
            'manufacturer': self.manufacturer,
            "removeretreadtyres": [tyre.to_dict() for tyre in self.removeretreadtyres],
            "removetyres": [tyre.to_dict() for tyre in self.removetyres],
            "oldtyres": [tyre.to_dict() for tyre in self.oldtyres],
            "stores": [spare.to_dict() for spare in self.stores],
            "mantainances": [mantainance.to_dict() for mantainance in self.mantainances],
            "fueling": [fuel.to_dict() for fuel in self.fueling],
            "invoices": [invoice.to_dict() for invoice in self.invoices],
            "bills": [bill.to_dict() for bill in self.bills],
            "used_tyres":[tyre.to_dict() for tyre in self.used_tyres]
        }
    
    def __repr__(self):
        return f"<Truck id={self.id}, truck_number={self.truck_number}, driver={self.driver}, vehicle_id={self.vehicle_id}>"
    
class Invoice(db.Model, SerializerMixin):
    __tablename__ = 'invoices'

    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String, nullable=False)
    invoice_number = db.Column(db.String, unique=True, nullable=False)
    customer_email = db.Column(db.String)
    vendor_pin = db.Column(db.String)
    type_vat = db.Column(db.String)
    amount_paid = db.Column(db.Float)
    amount_owed = db.Column(db.Float)
    status = db.Column(db.String)
    currency = db.Column(db.String)
    category_name = db.Column(db.String)
    customer_phone = db.Column(db.String)
    consignee = db.Column(db.String)
    order_number = db.Column(db.String)
    invoice_date = db.Column(db.String, nullable=False)
    invoice_terms = db.Column(db.String)
    due_date = db.Column(db.String, nullable=False)
    sales_person = db.Column(db.String)
    type_name = db.Column(db.String)
    
    category_id = db.Column(db.Integer, db.ForeignKey('account_categories.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)

    # Relationship to InvoiceItem
    items = db.relationship('InvoiceItem', backref='invoice', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'invoice_number': self.invoice_number,
            'customer_email': self.customer_email,
            'vendor_pin': self.vendor_pin,
            'type_vat': self.type_vat,
            'amount_owed': self.amount_owed,
            'amount_paid': self.amount_paid,
            'type_name': self.type_name,
            'category_id': self.category_id,
            'currency': self.currency,
            'status': self.status,
            'category_name': self.category_name,
            'customer_phone': self.customer_phone,
            'consignee': self.consignee,
            'order_number': self.order_number,
            'invoice_date': self.invoice_date,
            'invoice_terms': self.invoice_terms,
            'due_date': self.due_date,
            'sales_person': self.sales_person,
            'items': [item.to_dict() for item in self.items]
        }
    
    def __repr__(self):
        return (f"<Invoice id={self.id}, customer_name={self.customer_name}, invoice_number={self.invoice_number}"
                f"order_number={self.order_number}, invoice_date={self.invoice_date}, invoice_terms={self.invoice_terms}, "
                f"due_date={self.due_date}, sales_person={self.sales_person}, ")

class InvoiceItem(db.Model, SerializerMixin):
    __tablename__ = 'invoiceitems'

    id = db.Column(db.Integer, primary_key=True)
    invoice_id = db.Column(db.Integer, db.ForeignKey('invoices.id'), nullable=False)
    item_details = db.Column(db.String, nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    vat = db.Column(db.Integer)
    unit = db.Column(db.String)
    rate_vat = db.Column(db.Float)
    sub_total = db.Column(db.Float)
    description =db.Column(db.String)
    rate = db.Column(db.Float, nullable=False)
    amount = db.Column(db.Float, nullable=False)

    truck_id = db.Column(db.Integer, db.ForeignKey('trucks.id'))


    def to_dict(self):
        return {
            'id': self.id,
            'invoice_id': self.invoice_id,
            'item_details': self.item_details,
            'quantity': self.quantity,
            'unit': self.unit,
            'vat': self.vat,
            'truck_id': self.truck_id,
            'rate_vat': self.rate_vat,
            'sub_total': self.sub_total,
            'description': self.description,
            'rate': self.rate,
            'amount': self.amount
        }
    
    def __repr__(self):
        return (f"<InvoiceItem id={self.id}, invoice_id={self.invoice_id}, item_details={self.item_details}, "
                f"quantity={self.quantity}, rate={self.rate}, amount={self.amount}>")
    

class NewInvoice(db.Model, SerializerMixin):
    __tablename__ = 'newinvoices'

    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String, nullable=False)
    invoice_number = db.Column(db.String, unique=True, nullable=False)
    customer_email = db.Column(db.String)
    vendor_pin = db.Column(db.String)
    type_vat = db.Column(db.String)
    amount_paid = db.Column(db.Float)
    amount_owed = db.Column(db.Float)
    status = db.Column(db.String)
    currency = db.Column(db.String)
    category_name = db.Column(db.String)
    customer_phone = db.Column(db.String)
    consignee = db.Column(db.String)
    order_number = db.Column(db.String)
    invoice_date = db.Column(db.String, nullable=False)
    invoice_terms = db.Column(db.String)
    due_date = db.Column(db.String, nullable=False)
    sales_person = db.Column(db.String)
    fuel = db.Column(db.String)
    
    category_id = db.Column(db.Integer, db.ForeignKey('account_categories.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)

    invoice_item = db.relationship('TransactionReceivedInvoices', back_populates='invoice', lazy='selectin')  # New relationship


    # Relationship to InvoiceItem
    items = db.relationship('NewInvoiceItem', backref='newinvoice', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'invoice_number': self.invoice_number,
            'customer_email': self.customer_email,
            'vendor_pin': self.vendor_pin,
            'type_vat': self.type_vat,
            'amount_owed': self.amount_owed,
            'amount_paid': self.amount_paid,
            'category_id': self.category_id,
            'customer_id': self.customer_id,
            'currency': self.currency,
            'status': self.status,
            'category_name': self.category_name,
            'fuel': self.fuel,
            'customer_phone': self.customer_phone,
            'consignee': self.consignee,
            'order_number': self.order_number,
            'invoice_date': self.invoice_date,
            'invoice_terms': self.invoice_terms,
            'due_date': self.due_date,
            'sales_person': self.sales_person,
            'items': [item.to_dict() for item in self.items]
        }
    
    def __repr__(self):
        return (f"<NewInvoice id={self.id}, customer_name={self.customer_name}, invoice_number={self.invoice_number}"
                f"order_number={self.order_number}, invoice_date={self.invoice_date}, fuel={self.fuel}, invoice_terms={self.invoice_terms}, "
                f"due_date={self.due_date}, sales_person={self.sales_person}, ")

class NewInvoiceItem(db.Model, SerializerMixin):
    __tablename__ = 'newinvoiceitems'

    id = db.Column(db.Integer, primary_key=True)
    invoice_id = db.Column(db.Integer, db.ForeignKey('newinvoices.id'), nullable=False)
    item_details = db.Column(db.String, nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    vat = db.Column(db.Integer)
    unit = db.Column(db.String)
    rate_vat = db.Column(db.Float)
    sub_total = db.Column(db.Float)
    description =db.Column(db.String)
    rate = db.Column(db.Float, nullable=False)
    amount = db.Column(db.Float, nullable=False)

    truck_id = db.Column(db.Integer, db.ForeignKey('trucks.id'))


    def to_dict(self):
        return {
            'id': self.id,
            'invoice_id': self.invoice_id,
            'item_details': self.item_details,
            'quantity': self.quantity,
            'unit': self.unit,
            'vat': self.vat,
            'truck_id': self.truck_id,
            'rate_vat': self.rate_vat,
            'sub_total': self.sub_total,
            'description': self.description,
            'rate': self.rate,
            'amount': self.amount
        }
    
    def __repr__(self):
        return (f"<NewInvoiceItem id={self.id}, invoice_id={self.invoice_id}, item_details={self.item_details}, "
                f"quantity={self.quantity}, rate={self.rate}, amount={self.amount}>")
    
class DeliveryNote(db.Model, SerializerMixin):
    __tablename__ = 'deliverynotes'

    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String)
    truck_number = db.Column(db.String)
    customer_phone = db.Column(db.String)
    customer_email = db.Column(db.String)
    invoice_number = db.Column(db.String)
    delivery_number = db.Column(db.Integer)
    delivery_date = db.Column(db.Date)
    vendor_pin = db.Column(db.String)
    origin_place = db.Column(db.String)
    destination = db.Column(db.String)
    driver_contact = db.Column(db.String)
    driver = db.Column(db.String)

    # Relationship to InvoiceItem
    items = db.relationship('DeliveryNoteItem', backref='deliverynote', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'customer_name':self.customer_name,
            'truck_number': self.truck_number,
            'customer_phone' :self.customer_phone,
            'customer_email': self.customer_email,
            'invoice_number' : self.invoice_number,
            'delivery_number' : self.delivery_number,
            'delivery_date' : self.delivery_date,
            'vendor_pin' : self.vendor_pin,
            'origin_place': self.origin_place,
            'destination' : self.destination,
            'driver_contact' : self.driver_contact,
            'driver' :self.driver,
            'items': [item.to_dict() for item in self.items]
        }
    
    def __repr__(self):
        return (f"<DeliveryNote id={self.id}, customer_name={self.customer_name}, invoice_number={self.invoice_number}"
                f"truck_number={self.truck_number}, delivery_date={self.delivery_date}, origin_place={self.origin_place}, "
                f"destination={self.destination}, driver={self.driver}, ")

class DeliveryNoteItem(db.Model, SerializerMixin):
    __tablename__ = 'deliverynoteitems'

    id = db.Column(db.Integer, primary_key=True)
    deliverynote_id = db.Column(db.Integer, db.ForeignKey('deliverynotes.id'), nullable=False)
    container_number = db.Column(db.String, nullable=True)
    cargo_description = db.Column(db.String, nullable=True)
    quantity = db.Column(db.Float)
    weight = db.Column(db.Float)
    measurement = db.Column(db.String)

    def to_dict(self):
        return {
            'id': self.id,
            'deliverynote_id': self.deliverynote_id,
            'container_number': self.container_number,
            'cargo_description': self.cargo_description,
            'quantity': self.quantity,
            'weight': self.weight,
            'measurement': self.measurement,
        }
    
    def __repr__(self):
        return (f"<DeliveryNoteItem id={self.id}, deliverynote_id={self.deliverynote_id}, container_number={self.container_number}, "
                f"cargo_description={self.cargo_description}, quantity={self.quantity}, weight={self.weight}>")
    
    
class Customer(db.Model, SerializerMixin):

    __tablename__ = "customers"

    id = db.Column(db.Integer, primary_key=True)
    customer_type = db.Column(db.String, nullable=False)
    customer_name = db.Column(db.String(80))
    company_name = db.Column(db.String, nullable=True)
    customer_email= db.Column(db.String(80))
    customer_phone = db.Column(db.String)
    currency = db.Column(db.String(80), nullable=True)
    kra_pin = db.Column(db.String(80))
    amount_paid = db.Column(db.Float)
    payment_terms = db.Column(db.String(80), nullable=True)
    total_amount_owed = db.Column(db.Integer, nullable=True)

    invoices = db.relationship('NewInvoice', backref='customer', cascade="all, delete-orphan", lazy=True)
    credit_notes = db.relationship('CreditNote', backref='customer', cascade="all, delete-orphan", lazy=True)
    quotes = db.relationship('Quote', backref='customer', cascade="all, delete-orphan", lazy=True)


    def to_dict(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_type': self.customer_type,
            'company_name': self.company_name,
            'customer_email': self.customer_email,
            'customer_phone': self.customer_phone,
            'currency': self.currency,
            'amount_paid': self.amount_paid,
            'kra_pin': self.kra_pin,
            'payment_terms': self.payment_terms,
            "invoices": [invoice.to_dict() for invoice in self.invoices],
            "credit_notes": [items.to_dict() for items in self.credit_notes],
            "quotes": [items.to_dict() for items in self.quotes],
            'total_amount_owed': self.total_amount_owed
        }

    def __repr__(self):
        return (f"<Customer id={self.id}, customer_name={self.customer_name}, customer_type={self.customer_type}, company_name={self.company_name}, customer_email={self.customer_email}"
                f"customer_phone={self.customer_phone}, currency={self.currency}, opening_balance={self.opening_balance}, payment_terms={self.payment_terms}, total_amount_owed={self.total_amount_owed}>")
    
class TransactionReceived(db.Model):

    __tablename__ = "transactionsreceived"

    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String, nullable=False)
    customer_email = db.Column(db.String)
    customer_phone = db.Column(db.String)
    customer_pin = db.Column(db.String)
    currency = db.Column(db.String)
    amount_received = db.Column(db.Float, nullable=False)
    payment_date = db.Column(db.String(80), nullable=False)
    payment = db.Column(db.Float, nullable=False)
    payment_mode = db.Column(db.String(80), nullable=False)

    transaction_items = db.relationship('TransactionReceivedInvoices', backref='order', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_phone': self.customer_phone,
            'customer_email': self.customer_email,
            'customer_pin': self.customer_pin,
            'currency': self.currency,
            'amount_received': self.amount_received,
            'payment_date': self.payment_date,
            'payment': self.payment,
            'payment_mode': self.payment_mode,
            'invoices': [
                {
                    'invoice_id': item.invoice_id,
                    'amount_paid': item.invoice.amount_paid,
                    'amount_owed': item.invoice.amount_owed,
                    'status': item.invoice.status,
                    'customer_name': item.invoice.customer_name,
                    'invoice_date': item.invoice.invoice_date,
                    'invoice_number': item.invoice.invoice_number,
                    'invoice_total': sum(invoice_item.amount for invoice_item in item.invoice.items),
                }
                for item in self.transaction_items
            ]
        }

    def __repr__(self):
        return (f"<TransactionReceived id={self.id}, customer_name={self.customer_name}, amount_received={self.amount_received}, payment_date={self.payment_date}"
                f"payment={self.payment}, payment_mode={self.payment_mode},>")

class TransactionReceivedInvoices(db.Model):

    __tablename__ = "transactionsreceivedinvoices"

    id = db.Column(db.Integer, primary_key=True)
    transcation_id = db.Column(db.Integer, db.ForeignKey('transactionsreceived.id'), nullable=False)
    invoice_id = db.Column(db.Integer, db.ForeignKey('newinvoices.id'), nullable=False)

    invoice = db.relationship('NewInvoice', back_populates='invoice_item')

    def to_dict(self):
        return {
            'id': self.id,
            
        }

    def __repr__(self):
        return (f"<TransactionReceivedInvoices id={self.id}, >")

class Vendor(db.Model, SerializerMixin):
    __tablename__ = 'vendors'

    id = db.Column(db.Integer, primary_key=True)
    vendor_name = db.Column(db.String)
    vendor_email = db.Column(db.String)
    vendor_phone = db.Column(db.String)
    opening_balance = db.Column(db.Float, nullable=True)
    kra_pin = db.Column(db.String, nullable=False)
    currency = db.Column(db.String)
    amount_paid = db.Column(db.Float)
    total_amount_owed = db.Column(db.Float, nullable=False)

    bills = db.relationship('NewBill', backref='vendor', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'vendor_name': self.vendor_name,
            'currency':self.currency,
            'vendor_email': self.vendor_email,
            'vendor_phone': self.vendor_phone,
            'opening_balance': self.opening_balance,
            'kra_pin': self.kra_pin,
            'amount_paid': self.amount_paid,
            'total_amount_owed': self.total_amount_owed,
            'bills': [bill.to_dict() for bill in self.bills] if self.bills else [],  # Handle empty relationships
        }


    def __repr__(self):
        return (f"<Vendor id={self.id}, vendor_name={self.vendor_name}, vendor_email={self.vendor_email}, "
                f"vendor_phone={self.vendor_phone}, opening_balance={self.opening_balance}, total_amount_owed={self.total_amount_owed}>")
    
class AccountType(db.Model, SerializerMixin):
    __tablename__ = 'account_types'

    id = db.Column(db.Integer, primary_key=True)
    type_name = db.Column(db.String, nullable=False, unique=True)

    account_categories = db.relationship('AccountCategory', backref='account_type', cascade="all, delete-orphan", lazy=True)
    profit_and_loss_accounts = db.relationship('TradingProfitLossAccount', backref='account_type', cascade="all, delete-orphan", lazy=True)
    balancesheet = db.relationship('BalanceSheet', backref='account_type', cascade="all, delete-orphan", lazy=True)


    def to_dict(self):
        return {
            "id": self.id,
            "type_name": self.type_name,
            "account_categories": [category.to_dict() for category in self.account_categories],
            "profit_and_loss_accounts": [category.to_dict() for category in self. profit_and_loss_accounts],
            "balancesheet": [balance.to_dict() for balance in self.balancesheet]
        }

    def __repr__(self):
        return f"<AccountType id={self.id}, type_name={self.type_name}>"

class AccountCategory(db.Model, SerializerMixin):
    __tablename__ = 'account_categories'

    id = db.Column(db.Integer, primary_key=True)
    account_type_id = db.Column(db.Integer, db.ForeignKey('account_types.id'), nullable=False)
    type_name = db.Column(db.String)
    category_name = db.Column(db.String, nullable=False)
    amount = db.Column(db.Float)

    invoice_items = db.relationship('NewInvoice', backref='account_category', cascade="all, delete-orphan", lazy=True)
    bill_items = db.relationship('NewBill', backref='account_category', cascade="all, delete-orphan", lazy=True)
    credit_note_items = db.relationship('CreditNote', backref='account_category', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "account_type_id": self.account_type_id,
            "category_name": self.category_name,
            "type_name": self.type_name,
            'amount':self.amount,
            "invoice_items": [item.to_dict() for item in self.invoice_items],
            "bill_items": [item.to_dict() for item in self.bill_items],
            "credit_note_items": [item.to_dict() for item in self.credit_note_items],
        }

    def __repr__(self):
        return f"<AccountCategory id={self.id}, account_type_id={self.account_type_id}, category_name={self.category_name}>"
    
class TradingProfitLossAccount(db.Model, SerializerMixin):
    __tablename__ = 'trading_profit_loss_accounts'
    
    id = db.Column(db.Integer, primary_key=True)
    account_type_id = db.Column(db.Integer, db.ForeignKey('account_types.id'), nullable=False)
    type_name = db.Column(db.String)
    category_name = db.Column(db.String, nullable=False)
    amount = db.Column(db.Float)
    date = db.Column(db.Date)

    def to_dict(self):
        return {
            "id": self.id,
            "account_type_id": self.account_type_id,
            "category_name": self.category_name,
            "type_name":self.type_name,
            "amount": self.amount,
            'date':self.date,
        }
    
    def __repr__(self):
        return f"<TradingProfitLossAccount id={self.id}, account_type_id={self.account_type_id}, category_name={self.category_name}, date={self.date}>"
    
class BalanceSheet(db.Model, SerializerMixin):
    __tablename__ = 'balancesheets'
    
    id = db.Column(db.Integer, primary_key=True)
    account_type_id = db.Column(db.Integer, db.ForeignKey('account_types.id'), nullable=False)
    type_name = db.Column(db.String)
    category_name = db.Column(db.String, nullable=False)
    amount = db.Column(db.Float)
    date = db.Column(db.Date)

    def to_dict(self):
        return {
            "id": self.id,
            "account_type_id": self.account_type_id,
            "category_name": self.category_name,
            "type_name":self.type_name,
            "amount": self.amount,
            'date':self.date,
        }
    
    def __repr__(self):
        return f"<BalanceSheet id={self.id}, account_type_id={self.account_type_id}, category_name={self.category_name}, date={self.date}>"


class NewBill(db.Model, SerializerMixin):
    __tablename__ = 'newbills'

    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('account_categories.id'), nullable=False)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=False)
    vendor_name = db.Column(db.String)
    vendor_phone = db.Column(db.String)
    vendor_email = db.Column(db.String)
    bill_number = db.Column(db.String, unique=True)
    order_number = db.Column(db.String)
    category_name = db.Column(db.String)
    status = db.Column(db.String)
    bill_date = db.Column(db.String)
    payment_terms = db.Column(db.String)
    due_date = db.Column(db.String)
    type_vat = db.Column(db.String)
    currency = db.Column(db.String)
    vendor_pin = db.Column(db.String)
    amount_paid = db.Column(db.Integer)
    amount_owed = db.Column(db.Integer)
    type_name = db.Column(db.String)


    # Relationship to NewBillItem
    items = db.relationship('NewBillItem', backref='newbill', cascade="all, delete-orphan", lazy=True)

    bill_item = db.relationship('PaymentMadeBill', back_populates='bill', lazy='selectin')  # New relationship


    def to_dict(self):
        return {
            'id': self.id,
            'category_id': self.category_id,
            'vendor_id': self.vendor_id,
            'vendor_name': self.vendor_name,
            'category_name': self.category_name,
            'vendor_phone': self.vendor_phone,
            'vendor_email': self.vendor_email,
            'bill_number': self.bill_number,
            'order_number': self.order_number,
            'amount_paid': self.amount_paid,
            'amount_owed': self.amount_owed,
            'currency': self.currency,
            'status': self.status,
            'bill_date': self.bill_date,
            'type_name': self.type_name,
            'payment_terms': self.payment_terms,
            'due_date': self.due_date,
            'type_vat': self.type_vat,
            'vendor_pin': self.vendor_pin,
            'items': [item.to_dict() for item in self.items]  # Serializing items
        }

    def __repr__(self):
        return (f"<NewBill id={self.id}, vendor_name={self.vendor_name}, bill_number={self.bill_number}, "
                f"order_number={self.order_number}, bill_date={self.bill_date}, payment_terms={self.payment_terms}, "
                f"due_date={self.due_date}>")

class NewBillItem(db.Model, SerializerMixin):
    __tablename__ = 'newbillitems'

    id = db.Column(db.Integer, primary_key=True)
    bill_id = db.Column(db.Integer, db.ForeignKey('newbills.id'), nullable=False)
    item_details = db.Column(db.String, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    rate = db.Column(db.Float, nullable=False)
    sub_total = db.Column(db.Float)
    vat = db.Column(db.Integer, nullable=False)
    rate_vat = db.Column(db.Integer, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    spare_name = db.Column(db.String, nullable=True)
    unit = db.Column(db.String, nullable=True)
    description = db.Column(db.String, nullable=True)
    tyre_mileage = db.Column(db.String, nullable=True)
    measurement = db.Column(db.String, nullable=True)

    truck_id = db.Column(db.Integer, db.ForeignKey('trucks.id'))

    
    def to_dict(self):
        return {
            'id': self.id,
            'bill_id': self.bill_id,
            'item_details': self.item_details,
            'truck_id':self.truck_id,
            'quantity': self.quantity,
            'measurement': self.measurement,
            'rate': self.rate,
            'description': self.description,
            'unit': self.unit,
            'spare_name': self.spare_name,
            'sub_total': self.sub_total,
            'vat': self.vat,
            'rate_vat': self.rate_vat,
            'amount': self.amount,
            'tyre_mileage': self.tyre_mileage,
        }

    def __repr__(self):
        return (f"<NewBillItem id={self.id}, bill_id={self.bill_id}, item_details={self.item_details}, "
                f"quantity={self.quantity}, rate={self.rate}, vat={self.vat}, rate_vat={self.rate_vat}, "
                f"amount={self.amount}>")
    
class PaymentMade(db.Model, SerializerMixin):
    __tablename__ = 'paymentsmade'

    id = db.Column(db.Integer, primary_key=True)
    payment = db.Column(db.Integer)
    payment_amount = db.Column(db.Integer, nullable=False)
    payment_mode = db.Column(db.String, nullable=False)
    payment_date = db.Column(db.String, nullable=True)
    vendor_name = db.Column(db.String, nullable=False)
    vendor_phone = db.Column(db.String, nullable=True)
    vendor_email = db.Column(db.String, nullable=True)
    vendor_pin = db.Column(db.String, nullable=True)
    currency = db.Column(db.String)

    bill_items = db.relationship('PaymentMadeBill', backref='newbill', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'payment': self.payment,
            'payment_amount': self.payment_amount,
            'payment_mode': self.payment_mode,
            'payment_date': self.payment_date,
            'vendor_name': self.vendor_name,
            'vendor_phone': self.vendor_phone,
            'vendor_email': self.vendor_email,
            'vendor_pin': self.vendor_pin,
            'currency': self.currency,
            'bills': [
                {
                    'bill_id': item.bill_id,
                    'amount_paid': item.bill.amount_paid,
                    'amount_owed': item.bill.amount_owed,
                }
                for item in self.bill_items
            ]
        }

    def __repr__(self):
        return (f"<PaymentMade id={self.id}, payment_date={self.payment_date}, payment_amount={self.payment_amount}, "
                f"payment_mode={self.payment_mode}, payment_date={self.payment_date}, vendor_name={self.vendor_name}>")

class PaymentMadeBill(db.Model):

    __tablename__ = "paymentsmadebills"

    id = db.Column(db.Integer, primary_key=True)
    transcation_id = db.Column(db.Integer, db.ForeignKey('paymentsmade.id'), nullable=False)
    bill_id = db.Column(db.Integer, db.ForeignKey('newbills.id'), nullable=False)

    bill = db.relationship('NewBill', back_populates='bill_item')

    def to_dict(self):
        return {'id': self.id}

    def __repr__(self):
        return (f"<PaymentMadeBills id={self.id}, >")
    
class Total(db.Model, SerializerMixin):
    __tablename__ = 'totals'

    id = db.Column(db.Integer, primary_key=True)
    account_name = db.Column(db.String)
    amount = db.Column(db.Float)

    def __repr__(self):
        return f"<Total id={self.id}, account_name={self.account_name}, amount={self.amount}>"

class BankAccount(db.Model, SerializerMixin):
    __tablename__ = 'bankaccounts'

    id = db.Column(db.Integer, primary_key=True)
    bank_name = db.Column(db.String)
    bank_details = db.Column(db.String, nullable=False)
    currency = db.Column(db.String, nullable=False)
    amount = db.Column(db.Float, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'bank_name':self.bank_name,
            'bank_details': self.bank_details,
            'currency': self.currency,
            'amount': self.amount,
        }

    def __repr__(self):
        return (f"<BankAccount id={self.id},bank_details={self.bank_details}, "
                f"currency={self.currency}, amount={self.amount},")
    
class BankItem(db.Model, SerializerMixin):
    __tablename__ = 'bankitems'

    id = db.Column(db.Integer, primary_key=True)
    bank_name = db.Column(db.String)
    bank_details = db.Column(db.String, nullable=False)
    currency = db.Column(db.String, nullable=False)
    amount = db.Column(db.Float, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'bank_name':self.bank_name,
            'bank_details': self.bank_details,
            'currency': self.currency,
            'amount': self.amount,
        }

    def __repr__(self):
        return (f"<BankItem id={self.id},bank_details={self.bank_details}, "
                f"currency={self.currency}, amount={self.amount},")
    
class Funds(db.Model, SerializerMixin):
    __tablename__ = 'funds'

    id = db.Column(db.Integer, primary_key=True)
    fund_name = db.Column(db.String)
    currency = db.Column(db.String)
    amount = db.Column(db.Float)

    def __repr__(self):
        return f"<Funds id={self.id}, fund_name={self.fund_name}, amount={self.amount}>"

class Deposit(db.Model, SerializerMixin):
    __tablename__ = 'deposits'

    id = db.Column(db.Integer, primary_key=True)
    bank_name = db.Column(db.String)
    deposit_from = db.Column(db.String)
    currency = db.Column(db.String)
    bank_charges = db.Column(db.String)
    bank_details = db.Column(db.String)
    date = db.Column(db.Date)
    amount = db.Column(db.Float)

    def to_dict(self):
        return {
            'id': self.id,
            'bank_name': self.bank_name,
            'bank_details': self.bank_details,
            'currency': self.currency,
            'amount': self.amount,
            'deposit_from': self.deposit_from,
            'date': self.date,
            'bank_charges': self.bank_charges,
        }

    def __repr__(self):
        return f"<Deposit id={self.id}, bank_name={self.bank_name}, amount={self.amount}, date={self.date}, currency={self.currency}>"
    
class SpareCategory(db.Model, SerializerMixin):
    __tablename__ = 'sparecategories'

    id = db.Column(db.Integer, primary_key=True)
    spare_category_name = db.Column(db.String)

    items = db.relationship('SpareSubCategory', backref='newbill', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'spare_category_name': self.spare_category_name,
            'items': [item.to_dict() for item in self.items],
        }

    def __repr__(self):
        return f"<SpareCategory id={self.id}, spare_category_name={self.spare_category_name}>"

class SpareSubCategory(db.Model, SerializerMixin):
    __tablename__ = 'sparesubcategories'

    id = db.Column(db.Integer, primary_key=True)
    spare_subcategory_id = db.Column(db.Integer, db.ForeignKey('sparecategories.id'), nullable=True)
    spare_subcategory_name = db.Column(db.String, nullable=True)
    spare_category_name = db.Column(db.String)
    measurement = db.Column(db.String)
    date = db.Column(db.Date)
    price = db.Column(db.Float)
    quantity = db.Column(db.Float)

    def to_dict(self):
        return {
            'id': self.id,
            'spare_subcategory_name': self.spare_subcategory_name,
            'spare_subcategory_id': self.spare_subcategory_id,
            'quantity': self.quantity,
            'measurement': self.measurement,
            'spare_category_name': self.spare_category_name,
            'price':self.price,
            'date':self.date
        }

    def __repr__(self):
        return f"<SpareSubCategory id={self.id}, spare_subcategory_name={self.spare_subcategory_name}, spare_subcategory_id={self.spare_subcategory_id}, quantity={self.quantity}, date={self.date}>"

class PumpName(db.Model, SerializerMixin):
    __tablename__ = 'pumpnames'

    id = db.Column(db.Integer, primary_key=True)
    pump_name = db.Column(db.String)
    pump_location = db.Column(db.String)
    fuel_type = db.Column(db.String)
    litres = db.Column(db.Integer)
    initial_reading = db.Column(db.Integer)
    reading = db.Column(db.Integer)
    date = db.Column(db.Date)

    fuelings = db.relationship('PumpFueling', backref='newbill', cascade="all, delete-orphan", lazy=True)
    updates = db.relationship('PumpUpdate', backref='newbill', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'pump_name':self.pump_name,
            'pump_location':self.pump_location,
            'litres': self.litres,
            'initial_reading': self.initial_reading,
            'reading': self.reading,
            'date': self.date,
            'fuel_type': self.fuel_type,
            'fuelings': [item.to_dict() for item in self.fuelings],
            'updates': [item.to_dict() for item in self.updates],
    }

    def __repr__(self):
        return f"<PumpName id={self.id}, pump_name={self.pump_name}, litres={self.litres}, initial_reading={self.initial_reading}, date={self.date}>"
    
class PumpFueling(db.Model, SerializerMixin):
    __tablename__ = 'pumpfuelings'

    id = db.Column(db.Integer, primary_key=True)
    truck_id = db.Column(db.Integer, db.ForeignKey('trucks.id'), nullable=False)
    pump_id = db.Column(db.Integer, db.ForeignKey('pumpnames.id'), nullable=False)
    pump_location = db.Column(db.String)
    pump_name = db.Column(db.String)
    truck_number = db.Column(db.String)
    litres = db.Column(db.Integer)
    reading = db.Column(db.Integer)
    price = db.Column(db.Float)
    order = db.Column(db.String)
    date = db.Column(db.Date)

    def to_dict(self):
        return {
            'id': self.id,
            'pump_name':self.pump_name,
            'truck_number':self.truck_number,
            'pump_location':self.pump_location,
            'truck_id':self.truck_id,
            'pump_id':self.pump_id,
            'litres': self.litres,
            'reading': self.reading,
            'price': self.price,
            'order':self.order,
            'date': self.date,
    }

    def __repr__(self):
        return f"<PumpFueling id={self.id}, pump_name={self.pump_name}, litres={self.litres}, reading={self.reading}, date={self.date}>"
    
class PumpUpdate(db.Model, SerializerMixin):
    __tablename__ = 'pumpupdates'

    id = db.Column(db.Integer, primary_key=True)
    pump_id = db.Column(db.Integer, db.ForeignKey('pumpnames.id'), nullable=False)
    pump_name = db.Column(db.String)
    litres = db.Column(db.Integer)
    reading = db.Column(db.Integer)
    date = db.Column(db.Date)

    def to_dict(self):
        return {
            'id': self.id,
            'pump_name':self.pump_name,
            'pump_id':self.pump_id,
            'litres': self.litres,
            'reading': self.reading,
            'date': self.date,
    }

    def __repr__(self):
        return f"<PumpUpdate id={self.id}, pump_name={self.pump_name}, litres={self.litres}, reading={self.reading}, date={self.date}>"
    
class RetreadTyreTrip(db.Model, SerializerMixin):
    __tablename__ = 'retreadtyretrips'

    id = db.Column(db.Integer, primary_key=True)
    vendor_name = db.Column(db.String)
    vendor_phone = db.Column(db.String)
    vendor_email = db.Column(db.String)
    vendor_pin = db.Column(db.String)
    currency = db.Column(db.String)
    trip_number = db.Column(db.String)
    date = db.Column(db.Date)

    items = db.relationship('RetreadTyreTripItem', backref='retreadtyretrip', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'vendor_name':self.vendor_name,
            'vendor_phone':self.vendor_phone,
            'vendor_email':self.vendor_email,
            'trip_number': self.trip_number,
            'vendor_pin':self.vendor_pin,
            'currency':self.currency,
            'date':self.date,
            'items': [item.to_dict() for item in self.items]
        }

    def __repr__(self):
        return f"<RetreadTyreTrip id={self.id}, vendor_name={self.vendor_name}, vendor_phone={self.vendor_phone}, vendor_email={self.vendor_email}, vendor_pin={self.vendor_pin},>"
    
class RetreadTyreTripItem(db.Model, SerializerMixin):
    __tablename__ = 'retreadtyretripitems'

    id = db.Column(db.Integer, primary_key=True)
    shop_id = db.Column(db.Integer, db.ForeignKey('retreadtyretrips.id'), nullable=False)
    serial_number = db.Column(db.String, nullable=False)
    item_details = db.Column(db.String, nullable=False)
    size = db.Column(db.String, nullable=False)
    tyre_mileage = db.Column(db.Float, nullable=True)
    status = db.Column(db.Float, nullable=True)


    def to_dict(self):
        return {
            'id': self.id,
            'shop_id': self.shop_id,
            'item_details': self.item_details,
            'serial_number': self.serial_number,
            'status': self.status,
            'size': self.size,
            'tyre_mileage': self.tyre_mileage,

        }

    def __repr__(self):
        return (f"<RetreadTyreTripItem id={self.id}, shop_id={self.shop_id}, item_details={self.item_details}, "
                f"size={self.size}, tyre_mileage={self.tyre_mileage},")
    
class VehicleMantainance(db.Model, SerializerMixin):
    __tablename__ = 'vehiclemantainances'

    id = db.Column(db.Integer, primary_key=True)
    truck_id = db.Column(db.Integer, db.ForeignKey('trucks.id'), nullable=False)
    truck_number = db.Column(db.String)
    vehicle_type = db.Column(db.String)
    date = db.Column(db.Date)
    job_description = db.Column(db.String)
    manufacturer = db.Column(db.String)
    repair_number = db.Column(db.Float)

    items = db.relationship('VehicleMaintananceItem', backref='vehiclemantainance', cascade="all, delete-orphan", lazy=True)


    def to_dict(self):
        return {
            'id': self.id,
            'truck_id': self.truck_id,
            'date':self.date,
            'job_description' : self.job_description,
            'truck_number': self.truck_number,
            'repair_number':self.repair_number,
            'vehicle_type': self.vehicle_type,
            'manufacturer':self.manufacturer,
            'items': [item.to_dict() for item in self.items]

        }

    def __repr__(self):
        return f"<VehicleRepair id={self.id},  truck_id={self.truck_id}, date={self.date}>"
    
class VehicleMaintananceItem(db.Model, SerializerMixin):
    __tablename__ = 'vehiclemantainaceitems'

    id = db.Column(db.Integer, primary_key=True)
    job_name = db.Column(db.String)
    position = db.Column(db.String)
    mantainace_id = db.Column(db.Integer, db.ForeignKey('vehiclemantainances.id'), nullable=False)
    spare_subcategory_name = db.Column(db.String)
    spare_category_name = db.Column(db.String)
    quantity = db.Column(db.Float)
    price = db.Column(db.Float)
    mechanic = db.Column(db.String)


    def to_dict(self):
        return {
            'id': self.id,
            'spare_subcategory_name': self.spare_subcategory_name,
            'mantainance_id': self.mantainace_id,
            'quantity': self.quantity,
            'spare_category_name': self.spare_category_name,
            'mechanic': self.mechanic,
            'position': self.position,
            'job_name': self.job_name,
            'price': self.price,
        }

    def __repr__(self):
        return f"<VehicleRepair id={self.id}, spare_subcategory_name={self.spare_subcategory_name}, quantity={self.quantity}, mechanic={self.mechanic}, job_name={self.job_name}>"
    

class StockItem(db.Model, SerializerMixin):
    __tablename__ = 'stockitems'

    id = db.Column(db.Integer, primary_key=True)
    item_details = db.Column(db.String, nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    price = db.Column(db.Float)
    measurement = db.Column(db.String)
    store = db.Column(db.String)

    def to_dict(self):
        return {
            'id': self.id,
            'item_details': self.item_details,
            'quantity': self.quantity,
            'price': self.price,
            'measurement':self.measurement,
            'store':self.store,
        }

    def __repr__(self):
        return f"<StockItem id={self.id}, item_details={self.item_details}, quantity={self.quantity}, measurement={self.measurement}>"
    

class CreditNote(db.Model, SerializerMixin):
    __tablename__ = 'creditnotes'

    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('account_categories.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)
    customer_name = db.Column(db.String)
    customer_phone = db.Column(db.String)
    customer_email = db.Column(db.String)
    credit_number = db.Column(db.String, unique=True)
    category_name = db.Column(db.String)
    credit_date = db.Column(db.String)
    type_vat = db.Column(db.String)
    vendor_pin = db.Column(db.String)

    # Relationship to NewBillItem
    items = db.relationship('CreditNoteItem', backref='creditnote', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'category_id': self.category_id,
            'customer_id': self.customer_id,
            'customer_name': self.customer_name,
            'category_name': self.category_name,
            'customer_phone': self.customer_phone,
            'customer_email': self.customer_email,
            'credit_number': self.credit_number,
            'credit_date': self.credit_date,
            'type_vat': self.type_vat,
            'vendor_pin': self.vendor_pin,
            'items': [item.to_dict() for item in self.items]  # Serializing items
        }

    def __repr__(self):
        return (f"<CreditNote id={self.id}, vendor_name={self.vendor_name},")

class CreditNoteItem(db.Model, SerializerMixin):
    __tablename__ = 'creditnotesitems'

    id = db.Column(db.Integer, primary_key=True)
    credit_id = db.Column(db.Integer, db.ForeignKey('creditnotes.id'), nullable=False)
    item_details = db.Column(db.String, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    rate = db.Column(db.Float, nullable=False)
    sub_total = db.Column(db.Float)
    vat = db.Column(db.Integer, nullable=False)
    rate_vat = db.Column(db.Integer, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String, nullable=True)
    measurement = db.Column(db.String, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'credit_id': self.credit_id,
            'item_details': self.item_details,
            'quantity': self.quantity,
            'measurement': self.measurement,
            'rate': self.rate,
            'description': self.description,
            'sub_total': self.sub_total,
            'vat': self.vat,
            'rate_vat': self.rate_vat,
            'amount': self.amount,
        }

    def __repr__(self):
        return (f"<CreditNoteItem id={self.id}, bill_id={self.bill_id}, item_details={self.item_details}, "
                f"quantity={self.quantity}, rate={self.rate}, vat={self.vat}, rate_vat={self.rate_vat}, "
                f"amount={self.amount}>")
    
class CashBook(db.Model, SerializerMixin):
    __tablename__ = 'cashbooks'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    item_details = db.Column(db.String, nullable=False)
    bank = db.Column(db.String)
    bank_amount = db.Column(db.Float)
    cash_amount = db.Column(db.Float)
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date,
            'item_details': self.item_details,
            'bank': self.bank,
            'bank_amount': self.bank_amount,
            'cash_amount': self.cash_amount,
        }

    def __repr__(self):
        return (f"<CashBook id={self.id}, date={self.date}, item_details={self.item_details}, "
                f"bank={self.bank}, bank_amount={self.bank_amount}, vat={self.cash_amount}, ")
    
class CashBookDebit(db.Model, SerializerMixin):
    __tablename__ = 'cashbookdebits'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    item_details = db.Column(db.String, nullable=False)
    bank = db.Column(db.String)
    bank_amount = db.Column(db.Float)
    cash_amount = db.Column(db.Float)
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date,
            'item_details': self.item_details,
            'bank': self.bank,
            'bank_amount': self.bank_amount,
            'cash_amount': self.cash_amount,
        }

    def __repr__(self):
        return (f"<CashBookDebit id={self.id}, date={self.date}, item_details={self.item_details}, "
                f"bank={self.bank}, bank_amount={self.bank_amount}, vat={self.cash_amount}, ")
    
class Expense(db.Model, SerializerMixin):
    __tablename__ = 'expenses'

    id = db.Column(db.Integer, primary_key=True)
    expense_name = db.Column(db.String, nullable=False)
    expense_amount = db.Column(db.Float)

    def to_dict(self):
        return {
            'id': self.id,
            'expense_name': self.expense_name,
            'expense_amount': self.expense_amount,
        }

    def __repr__(self):
        return (f"<Expense id={self.id}, expense_name={self.expense_name}, expense_amount={self.expense_amount}, ")
    

class Quote(db.Model, SerializerMixin):
    __tablename__ = 'quotes'

    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String, nullable=False)
    quote_number = db.Column(db.Integer, unique=True, nullable=False)
    customer_email = db.Column(db.String)
    vendor_pin = db.Column(db.String)
    type_vat = db.Column(db.String)
    customer_phone = db.Column(db.String)
    quote_date = db.Column(db.Date, nullable=False)
    
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.id'), nullable=False)

    # Relationship QuoteItem
    items = db.relationship('QuoteItem', backref='quote', cascade="all, delete-orphan", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'quote_number': self.quote_number,
            'customer_email': self.customer_email,
            'vendor_pin': self.vendor_pin,
            'type_vat': self.type_vat,
            'customer_phone': self.customer_phone,
            'quote_date': self.quote_date,
            'items': [item.to_dict() for item in self.items]
        }
    
    def __repr__(self):
        return (f"<Invoice id={self.id}, customer_name={self.customer_name}, quote_number={self.quote_number}"
                f"type_vat={self.type_vat}, customer_phone={self.customer_phone}"
                f"quote_date={self.quote_date}, ")

class QuoteItem(db.Model, SerializerMixin):
    __tablename__ = 'quoteitems'

    id = db.Column(db.Integer, primary_key=True)
    quote_id = db.Column(db.Integer, db.ForeignKey('quotes.id'), nullable=False)
    item_details = db.Column(db.String, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    vat = db.Column(db.Integer)
    unit = db.Column(db.String)
    rate_vat = db.Column(db.Integer)
    sub_total = db.Column(db.Float)
    description =db.Column(db.String)
    quantity = db.Column(db.Integer, nullable=False)
    rate = db.Column(db.Float, nullable=False)
    amount = db.Column(db.Float, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'quote_id': self.quote_id,
            'item_details': self.item_details,
            'quantity': self.quantity,
            'unit': self.unit,
            'vat': self.vat,
            'rate_vat': self.rate_vat,
            'sub_total': self.sub_total,
            'description': self.description,
            'rate': self.rate,
            'amount': self.amount
        }
    
    def __repr__(self):
        return (f"<InvoiceItem id={self.id}, invoice_id={self.invoice_id}, item_details={self.item_details}, "
                f"quantity={self.quantity}, rate={self.rate}, amount={self.amount}>")