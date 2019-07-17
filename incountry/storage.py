import os

import requests
import json
import pdb

from .incountry_crypto import InCrypto


COUNTRIES_LIST_URL = 'http://portal-api-staging.incountry.io/countries'

class StorageError(Exception):
	pass

class StorageClientError(StorageError):
	pass

class StorageServerError(StorageError):
	pass


class Storage(object):
	def __init__(self, zone_id=None, api_key=None, endpoint=None, encrypt=True,
				secret_key=None):
		"""
			Returns a client to talk to the InCountry storage network. On init
			this class queries the storage network for the per-country API
			endpoints.

			@param zone_id: The id of the zone into which you wll store data
			@param api_key: Your API key
			@param endpoint: Host name for the storage API endpoint
			@param encrypt: Pass True (default) to encrypt values before storing
			@param secret_key: pass the encryption key for AES encrypting fields

			You can see parameters via env vars also:

			INC_ZONE_ID
			INC_API_KEY
			INC_ENDPOINT
			INC_SECRET_KEY
		"""
		self.zone_id = zone_id or os.environ.get('INC_ZONE_ID')
		if not self.zone_id:
			raise ValueError("Please pass zone_id param or set INC_ZONE_ID env var")

		self.api_key = api_key or os.environ.get('INC_API_KEY')
		if not self.api_key:
			raise ValueError("Please pass api_key param or set INC_API_KEY env var")

		self.endpoint = endpoint or os.environ.get('INC_ENDPOINT')
		if not self.endpoint:
			raise ValueError("Please pass endpoint param or set INC_ENDPOINT env var")

		self.encrypt = encrypt
		if encrypt:
			self.secret_key = os.environ.get('INC_SECRET_KEY')
			if not self.secret_key:
				raise ValueError(
					"Encryption is one. Please pass secret_key param or set INC_SECRET_KEY env var")
			self.crypto = InCrypto(self.secret_key)

		# Map of country code to dict with 'endpoint' and 'name'
		self.poplist = {} 
		# Load countries list. FIXME: Cache this data
		# TODO: Get country enpoint list working


	def load_country_endpoints(self):
		r = requests.get(COUNTRIES_LIST_URL)
		if r.status_code != 200:
			raise StorageClientError("Failed to retrieve country endpoint list")

		clist = r.json()
		if 'countries' in clist:
			for country in clist['countries']:
				if country['direct']:
					cc = country['id'].lower()
					# FIXME: Have countries API return the full endpoint
					self.poplist[cc] = \
						{'host': f"{cc}.api.incountry.io", 'name': country['name']}


	def write(self,
		country, 
		key, 
		body=None, 
		profile_key=None, 
		range_key=None,
		key2=None,
		key3=None):

		self.check_parameters(country, key)		
		country = country.lower()
		data = {"country":country, "key":key}
		if body:
			data['body'] = body
		if profile_key:
			data['profile_key'] = profile_key
		if range_key:
			data['range_key'] = range_key
		if key2:
			data['key2'] = key2
		if key3:
			data['key3'] = key3

		if self.encrypt:
			self.encrypt_data(data)

		r = requests.post(
			self.getendpoint(country, "/v2/storage/records"),
			headers=self.headers(),
			data=json.dumps(data))
		
		self.raise_if_server_error(r)

	def read(self, country, key):
		self.check_parameters(country, key)		
		country = country.lower()

		if self.encrypt:
			key = self.crypto.encrypt(key)
			
		r = requests.get(
			self.getendpoint(country, f"/v2/storage/records/{key}"),
			headers=self.headers())
		if r.status_code == 404:
			# Not found is ok
			return None

		self.raise_if_server_error(r)
		data = r.json()

		if self.encrypt:
			self.decrypt_data(data)

		return data


	def delete(self, country, key):
		self.check_parameters(country, key)		
		country = country.lower()

		if self.encrypt:
			key = self.crypto.encrypt(key)

		r = requests.delete(
			self.getendpoint(country, f"/v2/storage/records/{key}"),
			headers=self.headers())
		self.raise_if_server_error(r)
		return r.json()


	###########################################
	########### Common functions
	###########################################
	def encrypt_data(self, record):
		if self.secret_key is None:
			raise ValueError("Cannot encrypt data because secret_key is None")
		for k in ['key','body','profile_key','key2','key3']:
			if record.get(k, None):
				oldval = record[k]
				record[k] = self.crypto.encrypt(record[k])
				print("Encrypted len of {} is {}".format(oldval, len(record[k])))

	def decrypt_data(self, record):
		for k in ['key','body','profile_key','key2','key3']:
			if record.get(k, None):
				record[k] = self.crypto.decrypt(record[k])


	def getendpoint(self, country, path):
		# TODO: Make countries set cover ALL countries, indicating mini or med POP
		if not path.startswith("/"):
			path = f"/{path}"

		if country in self.poplist:
			return f"http://{self.poplist[country].host}{path}"
		else:
			return f"http://{self.endpoint}{path}"


	def headers(self):
		return {'Authorization': f'Bearer {self.api_key}',
				'x-zone-id': self.zone_id,
				'Content-Type': 'application/json'}


	def check_parameters(self, country, key):
		if country is None:
			raise StorageClientError("Missing country")
		if key is None:
			raise StorageClientError("Missing key")


	def raise_if_server_error(self, response):
		if response.status_code >= 400:
			raise StorageServerError( \
				"{} {} - {}".format(response.status_code, response.url, response.text))


