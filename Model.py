import pandas as pd
import numpy as np
import pickle
import matplotlib.pyplot as plt
from scipy import stats
import tensorflow as tf
import seaborn as sns
from pylab import rcParams
from sklearn.model_selection import train_test_split
from keras.models import Model, load_model, Sequential
from keras.layers import Input, Dense, TimeDistributed
from keras.layers.recurrent import LSTM
from keras.layers.core import Dense, Activation, Dropout
from keras.callbacks import ModelCheckpoint, TensorBoard, Callback
from keras import regularizers
import time
import csv
from dataReader import get_good_bad_data, get_all_data
from sklearn.metrics import mean_squared_error
from statistics import median
import random
from multiprocessing import Queue
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

save_path = "model_data/"

sequence_length = 100

loss_history_queue = Queue()
queue_lock = 1

def get_loss_queue():
    return loss_history_queue

def update_seq_size(to_size):
    global sequence_length
    sequence_length = to_size

class MyLossHistory(Callback):
    def on_epoch_end(self, epoch, logs={}):
        global loss_history_queue
        loss_history_queue.put(logs.get('loss'))


def create_train_test_data(path):
    ''' read the path and split it into good and bad timesteps '''
    data_set = get_good_bad_data(path, sequence_length)
    return data_set

def create_data_from_path(path):
    ''' read the path and return all timesteps with info array containing bad packets in timestep i '''
    data_set, info = get_all_data(path, sequence_length)
    return data_set, info

def predict_after_train(data_to_predict, path_to_model):
    autoencoder = load_model(path_to_model+"/model.hdf5")
    predicted = autoencoder.predict(data_to_predict)
    mses = []
    
    for indx in range(len(data_to_predict)):
        mse = mean_squared_error(data_to_predict[indx], predicted[indx])
        mses.append(mse)
        
    return mses

class TrainedModel():
    def __init__(self, path_to_model):
        self.model = load_model(path_to_model)

    def predict_window(self, window_to_predict):
        predicted = self.model.predict(window_to_predict)
        mse = mean_squared_error(window_to_predict[0], predicted[0])
        return mse  

def create_Model():    
    model = Sequential()
    layers = {'input': 50, 'hidden1': 40, 'hidden2': 20, 'hidden3': 40, 'output': 50}

    model.add(LSTM(
        input_shape=(sequence_length, layers['input']),
        units=layers['hidden1'],
        return_sequences=True))
    model.add(Dropout(0.2))
    
    
    model.add(LSTM(
            layers['hidden2'],
            return_sequences=True))
    model.add(Dropout(0.2))

    model.add(LSTM(
            layers['hidden3'],
            return_sequences=True))
    model.add(Dropout(0.2))
    

    model.add(TimeDistributed(Dense(units=layers['output'])))
    model.add(Activation("linear"))

    start = time.time()
    model.compile(loss="mean_squared_error", optimizer="adam")
    
    return model


def train(autoencoder, train, temp_save_path, nb_epoch = 100, batch_size = 32):
    global save_path
    save_path = temp_save_path
    
    checkpointer_save_path = save_path + "/model.hdf5"

    checkpointer = ModelCheckpoint(filepath=checkpointer_save_path, verbose=0, save_best_only=True)

    my_history = MyLossHistory()
    
    history = autoencoder.fit(train, train,
                        epochs=nb_epoch,
                        batch_size=batch_size,
                        validation_split=0.1,
                        verbose = 0,
                        callbacks=[checkpointer, my_history]).history
        

    return list_of_values
