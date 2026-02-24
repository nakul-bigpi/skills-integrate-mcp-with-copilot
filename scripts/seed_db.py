import json
from pymongo import MongoClient

# Load activities from seed_activities.json
with open('seed_activities.json') as f:
    activities = json.load(f)

client = MongoClient('mongodb://localhost:27017')
db = client['mergington']

# Remove existing activities and insert seed
print('Seeding activities...')
db.activities.delete_many({})
db.activities.insert_many(activities)
print('Done.')
