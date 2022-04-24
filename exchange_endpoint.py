from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback
from algosdk.v2client import algod
from algosdk import mnemonic
from algosdk import transaction
import time

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """
def is_valid(order_obj):
    if order_obj.creator_id != None:
        return True
    platform = order_obj.sell_currency
    tx_id = order_obj.tx_id
    if platform == "Ethereum":
        w3 = connect_to_eth()
        tx = w3.eth.get_transaction(tx_id)
        #print('Eth tx:')
        #print(tx)
        if (tx.get("value") == order_obj.sell_amount):
            if (tx.get("from") == order_obj.sender_pk):
                if (tx.get("to") == get_eth_keys()[1]):
                    return(True)
        pass
    elif platform == "Algorand":
        icl = connect_to_algo(connection_type='indexer')
        time.sleep(5)
        tx = icl.search_transactions(txid = tx_id).get('transactions')
        #print("algo tx:")
        #print(tx)
        if len(tx)>0:
            tx=tx[0]
            if (tx.get("payment-transaction").get("amount") == order_obj.sell_amount):
                if (tx.get("sender") == order_obj.sender_pk):
                    if (tx.get("payment-transaction").get("receiver") == get_algo_keys()[1]):
                        return(True)
        pass
        
        

    return(False)

def order_asdict(order):
    return {'sender_pk': order.sender_pk,'receiver_pk': order.receiver_pk, 'buy_currency': order.buy_currency, 'sell_currency': order.sell_currency, 'buy_amount': order.buy_amount, 'sell_amount': order.sell_amount, 'signature':order.signature,'tx_id':order.tx_id}

def check_sig(payload,sig):
    
    platform = payload.get('platform')

    pk = payload.get('sender_pk')
    result = False
    if platform == "Ethereum":
        eth_encoded_msg = eth_account.messages.encode_defunct(text =json.dumps(payload))
        
        if eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == pk:
                result = True
    elif platform == "Algorand":
        algo_encoded_msg = json.dumps(payload).encode('utf-8')
        if algosdk.util.verify_bytes(algo_encoded_msg,sig,pk):
            result = True
    return result

def log_message(message_dict):
    msg = json.dumps(message_dict)

    log_obj = Log()
    log_obj.message = msg
    
    g.session.add(log_obj)
    g.session.commit()
    
    return

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    mnemonic_secret = "dismiss silk all kitchen observe say sphere easy worry island boil faint guilt hobby cover torch they market beauty century satoshi party below abstract omit"
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = connect_to_eth()
    w3.eth.account.enable_unaudited_hdwallet_features()
    acct = w3.eth.account.from_mnemonic("shed blouse blur immune fat produce around million jeans lobster priority fluid")
    eth_pk = acct._address
    eth_sk = acct._private_key
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys

    return eth_sk, eth_pk
  
def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    fields = ['sender_pk','receiver_pk','buy_currency','sell_currency','buy_amount','sell_amount']
    
    unfilled_db = g.session.query(Order).filter(Order.filled == None).all()
    for existing_order in unfilled_db:
        

        if existing_order.buy_currency == order.sell_currency:
            if existing_order.sell_currency == order.buy_currency:
                if (existing_order.sell_amount / existing_order.buy_amount) >= (order.buy_amount/order.sell_amount) :
                    if is_valid(existing_order):
                        existing_order.filled = datetime.now()
                        order.filled = datetime.now()
                        existing_order.counterparty_id = order.id
                        #existing_order.counterparty = order_obj
                        order.counterparty_id = existing_order.id
                        #order_obj.counterparty = existing_order
                        tx_order = {'platform':order.buy_currency,'receiver_pk':order.receiver_pk,'order_id':order.id,'amount':order.buy_amount}
                        #print(tx_order['platform'])
                        #print(tx_order['receiver_pk'])
                        tx_xorder = {'platform':existing_order.buy_currency,'receiver_pk':existing_order.receiver_pk,'order_id':existing_order.id,'amount':order.buy_amount}
                        txes.append(tx_order)
                        txes.append(tx_xorder)
                        #print(order.counterparty_id)
                        #print(existing_order.counterparty_id)
                        g.session.commit()
                        if (existing_order.buy_amount > order.sell_amount) | (order.buy_amount > existing_order.sell_amount) :
                            if (existing_order.buy_amount > order.sell_amount):
                                parent = existing_order
                                counter = order
                            if order.buy_amount > existing_order.sell_amount:
                                parent = order
                                counter = existing_order
                            child = {}
                            child['sender_pk'] = parent.sender_pk
                            child['receiver_pk'] = parent.receiver_pk
                            child['buy_currency'] = parent.buy_currency
                            child['sell_currency'] = parent.sell_currency
                            child['buy_amount'] = parent.buy_amount-counter.sell_amount
                            child['sell_amount'] = (parent.buy_amount-counter.sell_amount)*(parent.sell_amount/parent.buy_amount)  
                            child_obj = Order(**{f:child[f] for f in fields})
                            child_obj.creator_id = parent.id
                            g.session.add(child_obj)
                        
                            g.session.commit()
                            break
                    
                        break
    execute_txes(txes)                    
    g.session.commit()
    
    pass
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    w3 = connect_to_eth()
    acl = connect_to_algo()

    algo_tx_ids = send_tokens_algo(acl,algo_sk,algo_txes)
    eth_tx_ids = send_tokens_eth(w3,eth_sk,eth_txes)
    fields = ['platform','receiver_pk','order_id']
    print(algo_txes[0])
    print(algo_tx_ids)
    i=0
    for tx in algo_txes:
        tx_obj = TX(**{f:tx[f] for f in fields})
        tx_obj.tx_id = algo_tx_ids[i]
        g.session.add(tx_obj)
        g.session.commit()
        i+1
        
    i=0
    for tx in eth_txes:
        tx_obj = TX(**{f:tx[f] for f in fields})
        tx_obj.tx_id = eth_tx_ids[i]
        g.session.add(tx_obj)
        g.session.commit()
        i+1

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    pass

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            eth_sk,eth_pk = get_eth_keys()
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #Your code here
            algo_sk,algo_pk = get_algo_keys()
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    #get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        sig = content.get('sig')
        payload = content.get('payload')
        # TODO: Check the signature
        if check_sig(payload,sig):
            order = content.get('payload')
            signature = content.get('sig')
    
        # 2. Add the order to the table
            fields = ['sender_pk','receiver_pk','buy_currency','sell_currency','buy_amount','sell_amount','tx_id']
            order_obj = Order(**{f:order[f] for f in fields})
            order_obj.signature = signature
            g.session.add(order_obj)
            g.session.commit()
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
            if is_valid(order_obj):
        # 3b. Fill the order (as in Exchange Server II) if the order is valid
                fill_order(order_obj)
                #print(txes)
                
                g.session.commit()
        # 4. Execute the transactions
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(True)

@app.route('/order_book')
def order_book():
    
    raw_db = g.session.query(Order).all()
    db = []
    for order in raw_db:
        db.append(order_asdict(order))
    #result = dict(data = db)
    result = {}
    result['data']=db
    #print(result)
    #Note that you can access the database session using g.session
    return jsonify(result)
    

if __name__ == '__main__':
    app.run(port='5002')
