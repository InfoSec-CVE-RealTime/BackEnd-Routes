from app import app
import redis
import pymongo

redisClient = redis.Redis(
    host=app.config['REDIS_SERVICE_HOST'], port=app.config['REDIS_SERVICE_PORT'])
