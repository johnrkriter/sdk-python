import incountry
from Crypto.Cipher import AES
import hashlib
from os import urandom
import incountry.InCrypto
import json
import ast

VERSION = 1;

class InCountry:
    def __init__( self, apikey, seed, account_country):
        self.apikey = apikey
        self.cipher = incountry.InCrypto.InCrypto(seed)
        
        config = incountry.Configuration()
        config.api_key['x-api-key'] = apikey
        api_client = incountry.ApiClient(config)
        self.api = incountry.DefaultApi(api_client)
        self.config = "{\"version\": "+str(VERSION)+", \"country\": \""+account_country+"\"}"
        
    def write(self, country, rowid, blob, **kwargs):
        rowid = self.cipher.encrypt(rowid)
        blob = self.cipher.encrypt(blob)
        if kwargs.get('key1'): kwargs['key1'] = self.cipher.hash(kwargs.get('key1'))
        if kwargs.get('key2'): kwargs['key2'] = self.cipher.hash(kwargs.get('key2'))
        if kwargs.get('key3'): kwargs['key3'] = self.cipher.hash(kwargs.get('key3'))
        if kwargs.get('key4'): kwargs['key4'] = self.cipher.hash(kwargs.get('key4'))
        if kwargs.get('key5'): kwargs['key5'] = self.cipher.hash(kwargs.get('key5'))
        self.api.write_post(config=self.config, country=country, rowid=rowid, blob=blob, **kwargs)
        
    def read(self, country, rowid):
        rowid = self.cipher.encrypt(rowid)
        data = self.api.read_post(config=self.config, country=country, rowid=rowid)
        return self.cipher.decrypt(data.blob)
        
    def delete(self, country, rowid):
        rowid = self.cipher.encrypt(rowid)
        self.api.delete_post(config=self.config, country=country, rowid=rowid)
        
    def lookup(self, country, **kwargs):
        key1 = kwargs.get('key1')
        key2 = kwargs.get('key2')
        key3 = kwargs.get('key3')
        key4 = kwargs.get('key4')
        key5 = kwargs.get('key5')
        if key1: kwargs['key1'] = self.cipher.hash(key1)
        if key2: kwargs['key2'] = self.cipher.hash(key2)
        if key3: kwargs['key3'] = self.cipher.hash(key3)
        if key4: kwargs['key4'] = self.cipher.hash(key4)
        if key5: kwargs['key5'] = self.cipher.hash(key5)
        data = self.api.lookup_post(config=self.config, country=country, **kwargs).blob
        data = json.loads(data)
        for loco in data:
            loco['key1'] = key1;
            loco['key2'] = key2;
            loco['key3'] = key3;
            loco['key4'] = key4;
            loco['key5'] = key5;
            loco['blob'] = self.cipher.decrypt(loco['blob'])
            loco['rowid'] = self.cipher.decrypt(loco['rowid'])
        return data

    def keylookup(self, country, **kwargs):
        if kwargs.get('key1'): kwargs['key1'] = self.cipher.hash(kwargs.get('key1'))
        if kwargs.get('key2'): kwargs['key2'] = self.cipher.hash(kwargs.get('key2'))
        if kwargs.get('key3'): kwargs['key3'] = self.cipher.hash(kwargs.get('key3'))
        if kwargs.get('key4'): kwargs['key4'] = self.cipher.hash(kwargs.get('key4'))
        if kwargs.get('key5'): kwargs['key5'] = self.cipher.hash(kwargs.get('key5'))
        data = self.api.keylookup_post(config=self.config, country=country, **kwargs).blob
        data = ast.literal_eval(data)
        
        rows = []
        for d in data: rows.append(self.cipher.decrypt(d))
        return rows
