from random import randint, choice as rc
from faker import Faker
from app import app
from models import db, Item,CashBook,DeliveryNoteItem,DeliveryNote,CashBookDebit,BankAccount,Quote,QuoteItem,Expense,PumpName,PumpFueling,PumpUpdate,CreditNote,CreditNoteItem,BalanceSheet,TradingProfitLossAccount,Total,StockItem,Funds,RetreadTyreTrip,RetreadTyreTripItem,ShopRetread,VehicleMaintananceItem,VehicleMantainance,BankItem,PaymentMade,Vendor,SpareCategory,SpareSubCategory, NewBill, NewBillItem, TransactionReceived,Customer, AccountType, AccountCategory, Invoice, InvoiceItem, Store, Update, Tyre, Removetyre, Truck, Purchase, RemoveRetreadtyre, RetreadTyre, RetreadTyreupdate,OldTyres
from datetime import datetime

fake = Faker()

with app.app_context():
    print("Deleting all records...")
    QuoteItem.query.delete()
    DeliveryNoteItem.query.delete()
    DeliveryNote.query.delete()
    Quote.query.delete()
    PumpUpdate.query.delete()
    CashBookDebit.query.delete()
    CashBook.query.delete()
    Total.query.delete()
    PumpFueling.query.delete()
    PumpName.query.delete()
    Expense.query.delete()
    StockItem.query.delete()
    PaymentMade.query.delete()
    SpareSubCategory.query.delete()
    BankItem.query.delete()
    SpareCategory.query.delete()
    Item.query.delete()
    Store.query.delete()
    Update.query.delete()
    Tyre.query.delete()
    Removetyre.query.delete()
    Purchase.query.delete()
    RemoveRetreadtyre.query.delete()
    RetreadTyre.query.delete()
    RetreadTyreupdate.query.delete()
    OldTyres.query.delete()
    NewBillItem.query.delete()
    NewBill.query.delete()
    InvoiceItem.query.delete()
    Invoice.query.delete()
    TransactionReceived.query.delete()
    Invoice.query.delete()
    Funds.query.delete()
    VehicleMaintananceItem.query.delete()
    VehicleMantainance.query.delete()
    RetreadTyreTripItem.query.delete()
    RetreadTyreTrip.query.delete()
    ShopRetread.query.delete()
    BankAccount.query.delete()
    TradingProfitLossAccount.query.delete()
    BalanceSheet.query.delete()
    CreditNoteItem.query.delete()
    CreditNote.query.delete()
    Truck.query.delete()
    Vendor.query.delete()
    Customer.query.delete()
    AccountCategory.query.delete()
    AccountType.query.delete()

    print("Creating items...")

    funds = []

    # Account Types
    fixed_assets = AccountType(type_name='Fixed Assets', id=1)
    current_assets = AccountType(type_name='Current Assets', id=2)
    capital_account = AccountType(type_name='Capital Account', id=3)
    long_term_liabilities = AccountType(type_name='Long Term Liabilities', id=4)
    short_term_liabilities = AccountType(type_name='Short Term Liabilities', id=5)
    expenses = AccountType(type_name='Expenses', id=6)
    cost_of_goods_sold = AccountType(type_name='Cost of Goods Sold', id=7)
    total_sales = AccountType(type_name='Sales', id=8)
    closing_stock = AccountType(type_name='Closing Stock',id=9)
    income = AccountType(type_name='Income',id=10)

    # Fixed Assets
    furniture = AccountCategory(category_name='Furniture', type_name='Fixed Assets', account_type_id=1, amount=0)
    vehicles = AccountCategory(category_name='Vehicles', type_name='Fixed Assets', account_type_id=1, amount=0)
    machinery_and_equipment = AccountCategory(category_name='Machinery and Equipment', type_name='Fixed Assets', account_type_id=1, amount=0)
    computer_hardware_and_software = AccountCategory(category_name='Computer Hardware and Software', type_name='Fixed Assets', account_type_id=1, amount=0)
    leasehold_assets = AccountCategory(category_name='Leasehold Assets', type_name='Fixed Assets', account_type_id=1, amount=0)
    land = AccountCategory(category_name='Land', type_name='Fixed Assets', account_type_id=1, amount=0)
    

    # Current Assets
    cash_at_bank = AccountCategory(category_name='Cash at Bank', type_name='Current Assets', account_type_id=2, amount=0)
    cash_at_hand = AccountCategory(category_name='Cash at Hand', type_name='Current Assets', account_type_id=2, amount=0)
    debtors = AccountCategory(category_name='Debtors', type_name='Current Assets', account_type_id=2, amount=0)
    general_income = AccountCategory(category_name='General Income', type_name='Current Assets', account_type_id=2, amount=0)
    stock = AccountCategory(category_name='Stock', type_name='Current Assets', account_type_id=2, amount=0)
    office_supplies = AccountCategory(category_name='Office Supplies', type_name='Current Assets', account_type_id=2, amount=0)
    raw_materials = AccountCategory(category_name='Raw Materials', type_name='Current Assets', account_type_id=2, amount=0)
    work_in_progress_goods = AccountCategory(category_name='Work in Progress Goods', type_name='Current Assets', account_type_id=2, amount=0)
    finished_goods = AccountCategory(category_name='Finished Goods', type_name='Current Assets', account_type_id=2, amount=0)
    merchandise_inventory = AccountCategory(category_name='Merchandise Inventory', type_name='Current Assets', account_type_id=2, amount=0)
    prepaid_rent = AccountCategory(category_name='Prepaid Rent', type_name='Current Assets', account_type_id=2, amount=0)
    prepaid_insurance = AccountCategory(category_name='Insurance Expense', type_name='Current Assets', account_type_id=2, amount=0)
    prepaid_taxes = AccountCategory(category_name='Taxes', type_name='Current Assets', account_type_id=2, amount=0)
    accrued_revenue = AccountCategory(category_name='Accrued Revenue', type_name='Current Assets', account_type_id=2, amount=0)
    

    # Long Term Liabilities
    long_term_loans = AccountCategory(category_name="Long Term Loans", type_name='Long Term Liabilities', account_type_id=4, amount=0)

    # Short Term Liabilities
    accrued_expenses = AccountCategory(category_name="Accrued Expenses", type_name='Short Term Liabilities', account_type_id=5, amount=0)
    unearned_revenue = AccountCategory(category_name="Unearned Revenue", type_name='Short Term Liabilities', account_type_id=5, amount=0)
    taxes_payable = AccountCategory(category_name="Taxes Payable", type_name='Short Term Liabilities', account_type_id=5, amount=0)
    unpaid_rent = AccountCategory(category_name="Unpaid Rent", type_name='Short Term Liabilities', account_type_id=5, amount=0)
    unpaid_wages = AccountCategory(category_name="Unpaid Wages", type_name='Short Term Liabilities', account_type_id=5, amount=0)
    creditor = AccountCategory(category_name="Creditors", type_name='Short Term Liabilities', account_type_id=5, amount=0)

    # Expenses
    advertising_and_marketing = AccountCategory(category_name="Advertising and Marketing", type_name='Expenses', account_type_id=6, amount=0)
    automobile_expense = AccountCategory(category_name="Automobile Expense", type_name='Expenses', account_type_id=6, amount=0)
    bad_debt = AccountCategory(category_name="Bad Debt", type_name='Expenses', account_type_id=6, amount=0)
    bank_fees_charges = AccountCategory(category_name="Bank Fees Charges", type_name='Expenses', account_type_id=6, amount=0)
    consultant_expense = AccountCategory(category_name="Consultant Expense", type_name='Expenses', account_type_id=6, amount=0)
    depreciation_expense = AccountCategory(category_name="Depreciation Expense", type_name='Expenses', account_type_id=6, amount=0)
    diesel_expense = AccountCategory(category_name="Diesel Expense", type_name='Expenses', account_type_id=6, amount=0)
    it_and_internet_expense = AccountCategory(category_name="IT and Internet Expense", type_name='Expenses', account_type_id=6, amount=0)
    janitorial_expense = AccountCategory(category_name="Janitorial Expense", type_name='Expenses', account_type_id=6, amount=0)
    lodging = AccountCategory(category_name="Lodging", type_name='Expenses', account_type_id=6, amount=0)
    postage = AccountCategory(category_name="Postage", type_name='Expenses', account_type_id=6, amount=0)
    printing_and_stationery = AccountCategory(category_name="Printing and Stationery", type_name='Expenses', account_type_id=6, amount=0)
    purchase_dicounts = AccountCategory(category_name="Purchase Discounts", type_name='Expenses', account_type_id=6, amount=0)
    rent_expense = AccountCategory(category_name="Rent Expense", type_name='Expenses', account_type_id=6, amount=0)
    salaries_and_emplyee_wages = AccountCategory(category_name="Salaries and Employee Wages", type_name='Expenses', account_type_id=6, amount=0)
    telephone_expense = AccountCategory(category_name="Telephone Expense", type_name='Expenses', account_type_id=6, amount=0)
    travel_expense = AccountCategory(category_name="Travel Expense", type_name='Expenses', account_type_id=6, amount=0)
    repairs_and_mantainace = AccountCategory(category_name="Repairs and Mantainance", type_name='Expenses', account_type_id=6, amount=0)
    meals_and_entertainment = AccountCategory(category_name="Meals and Entertainment", type_name='Expenses', account_type_id=6, amount=0)
    new_tyres = AccountCategory(category_name='New Tyres', type_name='Expenses', account_type_id=6, amount=0)
    spares = AccountCategory(category_name='Spare Parts', type_name='Expenses', account_type_id=6, amount=0)
    retread_tyres = AccountCategory(category_name='Retread Tyres', type_name='Expenses', account_type_id=6, amount=0)

    # Cost of Goods Availble for Sale
    sold_goods = AccountCategory(category_name="Cost of Goods Sold", type_name='Cost of Goods Sold', account_type_id=7, amount=0)

    # Sales
    inventory_sales = AccountCategory(category_name="Inventory Sales", type_name='Sales', account_type_id=8, amount=0)
    transport_sales = AccountCategory(category_name="Transport Sales", type_name='Sales', account_type_id=8, amount=0)
    other_sales = AccountCategory(category_name="Other Sales", type_name='Sales', account_type_id=8, amount=0)
    return_inwards = AccountCategory(category_name="Return Inwards", type_name='Sales', account_type_id=8, amount=0)

     # Closing Stock
    stock_closing = AccountCategory(category_name="Closing Stock", type_name='Closing Stock', account_type_id=9, amount=0)

    # Income
    discount = AccountCategory(category_name="Discount", type_name='Income', account_type_id=10, amount=0)
    general_income = AccountCategory(category_name="General Income", type_name='Income', account_type_id=10, amount=0)
    interest_income = AccountCategory(category_name="Interest Income", type_name='Income', account_type_id=10, amount=0)
    late_fee_income = AccountCategory(category_name="Late Fee Income", type_name='Income', account_type_id=10, amount=0)
    other_charges = AccountCategory(category_name="Other Charges", type_name='Income', account_type_id=10, amount=0)
    shipping_charge = AccountCategory(category_name="Shipping Charge", type_name='Income', account_type_id=10, amount=0)

    funds.extend([
            Funds(fund_name='Bank', amount="0", currency='KES'),
            Funds(fund_name='Undeposited Funds', amount="0", currency='KES'),
            Funds(fund_name='Petty Cash', amount="0", currency='KES')
    ])

    categories = [
            furniture, vehicles, machinery_and_equipment, computer_hardware_and_software,
            leasehold_assets, land, cash_at_bank, cash_at_hand, debtors, stock, office_supplies,
            raw_materials, work_in_progress_goods, finished_goods, merchandise_inventory,
            prepaid_rent, prepaid_insurance, prepaid_taxes, accrued_revenue, long_term_loans,
            accrued_expenses, unearned_revenue, taxes_payable, unpaid_rent, unpaid_wages,
            creditor, general_income, advertising_and_marketing, automobile_expense, bad_debt,
            bank_fees_charges, consultant_expense, depreciation_expense, it_and_internet_expense,
            janitorial_expense, lodging, postage, printing_and_stationery, purchase_dicounts,
            rent_expense, salaries_and_emplyee_wages, telephone_expense, travel_expense,
            repairs_and_mantainace, meals_and_entertainment, new_tyres, retread_tyres,
            sold_goods, inventory_sales, return_inwards,stock_closing,discount,general_income,interest_income,late_fee_income,other_charges,
            shipping_charge,transport_sales,diesel_expense,spares
        ]
    
    types = [
        fixed_assets,current_assets,capital_account,long_term_liabilities,short_term_liabilities,
        expenses,cost_of_goods_sold,total_sales,closing_stock,income
    ]



    db.session.add_all(funds + categories + types)
    db.session.commit()

    print("Items created successfully!")
    
