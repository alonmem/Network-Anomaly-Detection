import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.figure import Figure
import matplotlib.animation as animation
from matplotlib import style
from matplotlib import pyplot
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import threading
import urllib
import pandas as pd
import numpy as np
import sys
import Model
import multiprocessing
import os
import pandas
import random
from keras import backend
from matplotlib.colors import from_levels_and_colors
from matplotlib.collections import LineCollection
from sklearn.preprocessing import normalize
from keras.models import load_model
from sklearn.metrics import mean_squared_error
from matplotlib.lines import Line2D
from multiprocessing import Queue
import signal
import datetime
import tensorflow as tf
import numpy.core._methods 
import numpy.lib.format 
import matplotlib.backends.backend_tkagg 

LARGE_FONT = ("Times", 50)
NORM_FONT  = ("Verdana", 15)
SMALL_FONT = ("Verdana", 8)
button_font = ("Verdana", 23)
bg_color = "#87CEFA"

style.use("ggplot")

packetsRead = []
packet_counter = 0
stop = 0
update_graph_seconds = 0.5

f = Figure(facecolor=bg_color)
a = f.add_subplot(111)
a.set_axis_bgcolor('white')


collecting_figure = Figure(facecolor=bg_color)
traffic_while_sniffing = collecting_figure.add_subplot(111)
traffic_while_sniffing.set_title("Loss")
traffic_while_sniffing.set_axis_bgcolor('white')

training_figure = Figure(facecolor=bg_color)
training_loss_vals = training_figure.add_subplot(111)
training_loss_vals.set_title("Packets Collected")
training_loss_vals.set_axis_bgcolor('white')

strat_index_for_collecting = -1
stop_collecting = 0
collected_packet_counter = 0
collection_thread = []

training_process = []
done_train = 0
training_process_id = Queue()
training_process_id_2 = Queue()
last_training_size = 0
loss_vals_array = []

packets_data_path = None
model_path = None
path_to_csv = None
model_is_loaded = False
path_to_anomaly = None

back_to_page = None

in_mainPage = False

threshold_window = None

data_for_training = []
colors_for_analyze = []
packets_time = []
arr_lock = threading.Lock()

def check_pid(pid):        
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True

def update_threshold_after_load():
    model_dir =(model_path + '.')[:-1]
    while model_dir[-1] != "/":
        model_dir = model_dir[:-1]
    
    with open(model_dir+"mses_of_train.pickle", "rb") as f:
        global threshold_window
        mses = pickle.load(f)
        threshold_window = max(mses)

def train_model(epochs, window_size, batch_size):
    global sequence_length
    global done_train
    global training_process_id
    training_process_id.put(os.getpid())
    training_process_id_2.put(os.getpid())
    
    Model.update_seq_size(window_size)
    data, infos = Model.create_data_from_path(path_to_csv)
    model = Model.create_Model()
    Model.train(model, data, model_path, nb_epoch=epochs, batch_size=batch_size)

def after_training():
    global threshold_window
    mses = Model.predict_after_train(np.array(data_for_training), model_path)
    threshold_window = max(mses)
    with open(model_path+"/mses_of_train.pickle", 'wb') as file_pi:
        pickle.dump(mses, file_pi, protocol=pickle.HIGHEST_PROTOCOL)

    with open(model_path+"/lossHistory.pickle", 'wb') as file_pi:
        pickle.dump(loss_vals_array, file_pi, protocol=pickle.HIGHEST_PROTOCOL)

def update_stop_collecting():
    global stop_collecting
    stop_collecting = 1
    
def stop_training():
    try:
        if not training_process_id_2.empty():
            pid = training_process_id_2.get()
            os.kill(pid, signal.SIGKILL)
            training_process[0].terminate()
            training_process[0].join()
    except:
        print("error in stop training")
    
def packet_callback(p):
    global collected_packet_counter
    collected_packet_counter+=1
    if stop_collecting:
        return 1
    return stop

def generate_csv_features(path_to_pcap, save_dir, save=True):
    scapy_cap = None
    if save:
        scapy_cap = rdpcap(path_to_pcap)
    else:
        scapy_cap = path_to_pcap

    list_of_values = Model.test_filter(scapy_cap)

    if save:
        global path_to_csv
        my_data = pandas.DataFrame(list_of_values)
        my_data.to_csv(save_dir + "/dataFeatures.csv", index=False, header=None)
        path_to_csv = packets_data_path + "/dataFeatures.csv"
    else:
        return list_of_values


def collect_data_thread(sec_to_collect):
    global packets_data_path
    packets_collected = sniff(timeout=sec_to_collect, stop_filter=packet_callback)
    wrpcap(packets_data_path+"/data.pcap",packets_collected)
    generate_csv_features(packets_data_path+"/data.pcap", packets_data_path)
    packets_data_path = packets_data_path+"/data.pcap"


last_len_when_animated = 0
traffic_to_animate = []
traffic_to_animate_time = []
def animate_live_detection():
    legend_elements = [Line2D([0], [0], color='b', lw=2, label='not-analyzed'),
                   Line2D([0], [0], color='g', lw=2, label='OK'),
                   Line2D([0], [0], color='r', lw=2, label='anomaly')]
    legend = a.legend(handles=legend_elements, loc='upper right')
    legend.get_frame().set_facecolor('#e1f5ff')
    a.set_xlabel('time')
    a.set_ylabel('packets collected')

    arr_lock.acquire()
    x = traffic_to_animate_time
    y = traffic_to_animate
    
    x_time = []
    for i in x:
        x_time.append(datetime.datetime.fromtimestamp(int(i)).strftime('%H:%M:%S'))

    for i in range(len(traffic_to_animate)-1):
        curr = traffic_to_animate_time[i]
        color_to_paint = 'b'
        for color in colors_for_analyze:
            if curr <= color[0][1] and curr >= color[0][0]:
                color_to_paint = color[1]
                
        a.plot([x[i],x[i+1]], [y[i],y[i+1]], color_to_paint)
        
    a.set_xticklabels(x_time[1:], fontdict=None, minor=False)
    arr_lock.release()
    

def animate(i):
    global last_len_when_animated
    global traffic_to_animate
    global traffic_to_animate_time
    traffic_to_animate.append(len(packetsRead) - last_len_when_animated)
    traffic_to_animate_time.append(time.time())
    last_len_when_animated = len(packetsRead)
    
    a.clear()
    if in_mainPage:
        animate_live_detection()
    
    traffic_while_sniffing.clear()
    if strat_index_for_collecting != -1 and not in_mainPage:
        traffic_while_sniffing.set_title("Traffic", fontdict={'fontsize': 20})
        traffic_while_sniffing.set_xlabel('time')
        traffic_while_sniffing.set_ylabel('packets collected')

        traffic_while_sniffing.plot(traffic_to_animate[strat_index_for_collecting:])
        traffic_while_sniffing.set_xticklabels([datetime.datetime.fromtimestamp(int(i)).strftime('%H:%M:%S')for i in traffic_to_animate_time[strat_index_for_collecting:]],
                                               fontdict=None, minor=False)
        
    if not in_mainPage:
        training_loss_vals.clear()
        training_loss_vals.set_title("Training Loss", fontdict={'fontsize': 20})
        training_loss_vals.set_xlabel('epoch')
        training_loss_vals.set_ylabel('loss')

        training_loss_vals.plot(loss_vals_array)


def popupmsg(msg):
    popup = tk.Tk()
        
    popup.wm_title("!")
    label = ttk.Label(popup, text = msg, font = NORM_FONT)
    label.pack(side = "top", fill="x", pady=10)
    button1 = ttk.Button(popup, text="Okay", command = popup.destroy)
    button1.pack()
    popup.mainloop()

protocols_dict_2 = dict()
services_dict_2 = dict()

def filter_packet_2(packet):
    global protocols_dict_2
    global services_dict_2
    filtered_packet = packet.copy()
    filtered_packet.pop() #label
    filtered_packet.pop() # attack type
    filtered_packet.pop(5) # protocol state
    
    srcIP = filtered_packet[0].split('.')
    dstIP = filtered_packet[2].split('.')
    proto = filtered_packet[4]
    service = filtered_packet[12]
    dstPort = packet[3]
    srcPort = packet[1]

    filtered_packet.pop(0) # source IP
    filtered_packet.pop(1) # destination IP
    filtered_packet.pop(2) # Protocol
    filtered_packet.pop(9) # Service

    filtered_packet = srcIP + filtered_packet
    filtered_packet1 = filtered_packet[:5] + dstIP + filtered_packet[5:]

    if proto not in protocols_dict_2:
        protocols_dict_2[proto] = len(protocols_dict_2)
        
    filtered_packet1.insert(10, protocols_dict_2[proto])
    
    if service not in services_dict_2:
        services_dict_2[service] = len(services_dict_2)
        
    filtered_packet1.insert(10, services_dict_2[service])

    if srcPort == '-':
        srcPort = -1
    if dstPort == '-':
        dstPort = -1
    for i in range(len(filtered_packet1)):
        if filtered_packet1[i] == '' or filtered_packet1[i] == ' ':
            filtered_packet1[i] = -1
    
    try:
        int(srcPort)
    except:
        srcPort = int(srcPort, 16)
    filtered_packet1[4] = srcPort
    
    try:
        int(dstPort)
    except:
        dstPort = int(dstPort, 16)
    filtered_packet1[9] = dstPort
        
    final_packet = [float(i) for i in filtered_packet1]
    del final_packet[33:35] # start&end time

    return final_packet

packetsRead_pcap = []
def anlayze_realtime_packets():
    global packetsRead_pcap
    backend.clear_session()
    my_model = None
    if model_is_loaded:
        my_model = Model.TrainedModel(model_path)
    else:
        my_model = Model.TrainedModel(model_path+"/model.hdf5")

    while not stop:
        packets_to_analyze = []
        if len(packetsRead_pcap) > 100:
            packets_to_analyze = packetsRead_pcap[:100]
            packetsRead_pcap = packetsRead_pcap[100:]
        else:
            continue
        
        first_time = packets_to_analyze[0].time
        last_time = packets_to_analyze[-1].time
        
        all_packets = generate_csv_features(packets_to_analyze, None, save=False)
        all_filtered_packets = []
        for pkt in all_packets:
            vec = filter_packet_2(pkt)
            if len(vec) == 50:
                all_filtered_packets.append(vec)
        while len(all_filtered_packets) < 100:
            all_filtered_packets.append(all_filtered_packets[-1])
            
        all_norm_packets = normalize(np.array(all_filtered_packets, dtype = np.float32))
        to_predict = np.array([all_norm_packets])

        mse = my_model.predict_window(to_predict)
        global colors_for_analyze
        if mse >= threshold_window: # anomaly
            colors_for_analyze.append(((first_time, last_time), 'r'))
            for pkt in packets_to_analyze:
                wrpcap(path_to_anomaly, pkt, append=True)

        else:
            colors_for_analyze.append(((first_time, last_time), 'g'))


oneTimeBool = False
analyzing_thread = threading.Thread(target = anlayze_realtime_packets)

def clear_before_mainPage():
    global last_len_when_animated
    global traffic_to_animate
    global traffic_to_animate_time
    arr_lock.acquire()

    last_len_when_animated = 0
    traffic_to_animate = []
    traffic_to_animate_time = []

    packetsRead = []
    oneTimeBool = True
    if not analyzing_thread.isAlive():
        analyzing_thread.start()
    arr_lock.release()


def readPackets():
    def add_pkt_to_array(pkt):
        global packetsRead_pcap
        global colors_for_analyze
        global packetsRead
        global packets_time
        global oneTimeBool
        global analyzing_thread

        packetsRead.append(1)
        packetsRead_pcap.append(pkt)
        packets_time.append(pkt.time)

        return stop
            
    sniff(stop_filter=add_pkt_to_array)


def close_all():
    global stop
    global app
    stop = 1
    packets_thread.join()
    if len(collection_thread)!= 0 and collection_thread[0].isAlive():
        collection_thread[0].join()
    if analyzing_thread.isAlive():
        analyzing_thread.join()
    stop_training()
    app.destroy()
    
class AnomalyDetectionApp(tk.Tk):

    def __init__(self, *args, **kwargs):
        
        tk.Tk.__init__(self, *args, **kwargs)

        tk.Tk.wm_title(self, "Anomaly Detection")

        
        container = tk.Frame(self)
        container.pack(side="top", fill = "both", expand = True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        menubar = tk.Menu(container)
        
        filemenu = tk.Menu(menubar, tearoff = 0, bg="white")
        filemenu.add_command(label = "Exit", command = close_all)
        menubar.add_cascade(label = "Options", menu = filemenu)
        
        tk.Tk.config(self, menu = menubar)

        self.frames = {}
        myFrames = (StartPage, TrainPage, MainPage, CollectData)

        for f in myFrames:
            frame = f(container, self)
            self.frames[f] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(StartPage)


    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
    

class StartPage(tk.Frame):

    def __init__(self, parent, controller):
        
        tk.Frame.__init__(self, parent, bg=bg_color)
        style_for_button = ttk.Style()
        style_for_button.configure('FontChooser.TButton', font=button_font, background = "mint cream", activeforeground = "mint cream")

        label = tk.Label(self, text="Start Page", font=LARGE_FONT, bg=bg_color)
        label.pack(pady=10, padx=10)
        
        self.collect_data_button = ttk.Button(self, text="Collect Data", style='FontChooser.TButton',
                            command=lambda: self.browse_for_data(controller, "collect"))
                                           

        self.load_data_button = ttk.Button(self, text="Load Data", style='FontChooser.TButton',
                            command=lambda: self.browse_for_data(controller, "load"))
        
        
        def load_selected(controller):
            self.browse_for_model(controller)
            
        def train_selected():
            self.train_model_button.place_forget()
            self.load_data_button.place(x=660, y=150, height=200, width= 500)
            self.collect_data_button.place(x=660, y=450, height=200, width= 500)
            
        load_model_button = ttk.Button(self,text="Load Model",  style='FontChooser.TButton', command=lambda: load_selected(controller))
        load_model_button.place(x=100, y=150, height=200, width= 500)
        self.train_model_button = ttk.Button(self,text="Train Model", command=train_selected, style='FontChooser.TButton')
        self.train_model_button.place(x=100, y=450, height=200, width= 500)

        

    def browse_for_data(self, controller, comnd):
        global packets_data_path
        global path_to_csv

        if comnd == "collect":
            filename = tk.filedialog.askdirectory(initialdir = "/",
                                                  title = "Select Folder To Save Data")
                                                  

            if type(filename) is str and "/" in filename:
                packets_data_path = filename
                controller.show_frame(CollectData)

        else:
            filename = tk.filedialog.askopenfilename(initialdir = "/",
                                                  title = "Select Data File",
                                                  filetypes = [("csv file","*.csv")])

            if type(filename) is str and "/" in filename:
                path_to_csv = filename
                controller.show_frame(TrainPage)

    def browse_for_model(self, controller):
        global model_path
        global path_to_anomaly
        filename = tk.filedialog.askopenfilename(initialdir = "/",
                                                  title = "Select Model File",
                                                  filetypes = [("model file","*.hdf5")])

        if type(filename) is str and "/" in filename:
            model_path = filename
            clear_before_mainPage()
            global in_mainPage
            global model_is_loaded
            path_to_anomaly = filename[:-1] + filename[-1]
            while True:
                if path_to_anomaly[-1] == '/':
                    break
                path_to_anomaly = path_to_anomaly[:-1]
                
            path_to_anomaly = path_to_anomaly + "anomaly.pcap"
            model_is_loaded = True
            in_mainPage = True
            update_threshold_after_load()
            clear_before_mainPage()
            controller.show_frame(MainPage)
        else:
            self.train_model_button.place(x=100, y=450, height=200, width= 500)
            self.load_data_button.place_forget()
            self.collect_data_button.place_forget()


class TrainPage(tk.Frame):
    def __init__(self, parent, controller):
        
        tk.Frame.__init__(self, parent, bg = bg_color)

        style_for_button = ttk.Style()
        style_for_button.configure('FontChooser.TButton', font=NORM_FONT, background = "mint cream")

        label = tk.Label(self, text="Model Training", font=LARGE_FONT, bg = bg_color)
        label.pack(pady=10, padx=10)

        start_train_button = ttk.Button(self, text="Start Training", style = "FontChooser.TButton",
                            command=lambda: start_training_clicked())
        start_train_button.place(x=900, y=110, height=85, width=180)

        stop_train_button = ttk.Button(self, text="Stop Training", style = "FontChooser.TButton",
                            command=lambda: stop_train_clicked())

        window_size_label = tk.Label(self, text="window size:", font=NORM_FONT, bg = bg_color)
        window_size_label.place(x=100, y=110, height=85, width=180)
        
        window_size_choices = ["50", "100", "200"]
        window_size = tk.StringVar(self)
        window_size.set("100")

        window_size_menu = tk.OptionMenu(self, window_size, *window_size_choices)
        window_size_menu.config(bg = "mint cream")
        window_size_menu["menu"].config(bg="mint cream")
        window_size_menu["disabledforeground"] = "mint cream"
        window_size_menu["activebackground"] = "mint cream"
        window_size_menu["highlightbackground"] = bg_color

        window_size_menu.place(x=275, y=139, height=30, width=70)

        batch_size_label = tk.Label(self, text="batch size:", font=NORM_FONT, bg = bg_color)
        batch_size_label.place(x=365, y=110, height=85, width=180)
        
        batch_size_choices = ["8", "32", "64", "128"]
        batch_size = tk.StringVar(self)
        batch_size.set("32")

        batch_size_menu = tk.OptionMenu(self, batch_size, *batch_size_choices)
        batch_size_menu.config(bg = "mint cream")
        batch_size_menu["menu"].config(bg="mint cream")
        batch_size_menu["disabledforeground"] = "mint cream"
        batch_size_menu["activebackground"] = "mint cream"
        batch_size_menu["highlightbackground"] = bg_color
        batch_size_menu.place(x=530, y=139, height=30, width=70)

        epochs_label = tk.Label(self, text="epochs:", font=NORM_FONT, bg = bg_color)
        epochs_label.place(x=630, y=110, height=85, width=130)
        
        epochs_choices = ["50", "100", "200", "1000"]
        epoch_size = tk.StringVar(self)
        epoch_size.set("50")

        epoch_menu = tk.OptionMenu(self, epoch_size, *epochs_choices)
        epoch_menu.config(bg = "mint cream")
        epoch_menu["menu"].config(bg="mint cream")
        epoch_menu["disabledforeground"] = "mint cream"
        epoch_menu["activebackground"] = "mint cream"
        epoch_menu["highlightbackground"] = bg_color
        epoch_menu.place(x=750, y=139, height=30, width=70)

        canvas = FigureCanvasTkAgg(training_figure, self)
        canvas.show()


        epoch_size_selected = tk.Label(self, textvariable=epoch_size, font=NORM_FONT, bg= bg_color)
        window_size_selected = tk.Label(self, textvariable=window_size, font=NORM_FONT, bg= bg_color)
        batch_size_selected = tk.Label(self, textvariable=batch_size, font=NORM_FONT, bg= bg_color)


        def update_log_text():
            global last_training_size
            global loss_vals_array
            
            loss_history_queue = Model.get_loss_queue()
            q_size = loss_history_queue.qsize()
            
            if int(epoch_size.get())-2 <= q_size:
                global in_mainPage
                in_mainPage = True
                clear_before_mainPage()
                controller.show_frame(MainPage)
                
            if  q_size> last_training_size:
                last_training_size = q_size
                loss_vals_array.append(loss_history_queue.get())

            self.after(2000, update_log_text)

        def start_training_clicked():
            if not self.browse_for_model(controller):
                return
            
            stop_train_button.place(x=900, y=110, height=85, width=180)
            start_train_button.place_forget()

            epoch_size_selected.place(x=735, y=139, height=30, width=55)
            window_size_selected.place(x=260, y=139, height=30, width=55)
            batch_size_selected.place(x=515, y=139, height=30, width=55)
            
            epoch_menu.place_forget()
            batch_size_menu.place_forget()
            window_size_menu.place_forget()

            canvas._tkcanvas.place(relx=0, rely =0.3, relheight = 0.7, relwidth=1)
            canvas.get_tk_widget().place(relx=0, rely =0.3, relheight = 0.7, relwidth = 1)

            global data_for_training
            data, infos = Model.create_data_from_path(path_to_csv)
            data_for_training = data


            Model.update_seq_size(window_size)
            train_process = multiprocessing.Process(target=train_model,
                                                    args=(int(epoch_size.get()), int(window_size.get()), int(batch_size.get())))

            training_process.append(train_process)
            train_process.start()
            update_log_text()

        def stop_train_clicked():
            while True:
                try:
                    stop_training()
                    after_training()

                    global in_mainPage
                    in_mainPage = True
                    clear_before_mainPage()
                    controller.show_frame(MainPage)
                    break
                except:
                    pass

    def browse_for_model(self, controller):
        global model_path
        global path_to_anomaly
        model_folder = tk.filedialog.askdirectory(initialdir = "/",
                                                  title = "Select folder to save model")

        if type(model_folder) is str and "/" in model_folder:
            model_path = model_folder
            path_to_anomaly = model_folder + "/anomaly.pcap"
            return True
        return False



class CollectData(tk.Frame):
    def __init__(self, parent, controller):
        
        tk.Frame.__init__(self, parent, bg=bg_color)

        style_for_button = ttk.Style()
        style_for_button.configure('FontChooser.TButton', font=NORM_FONT, background = "mint cream")

        
        label = tk.Label(self, text="Collect Data", font=LARGE_FONT, bg = bg_color)
        label.pack(pady=10, padx=10)

        start_collect_button = ttk.Button(self, text="Start collecting ", style = "FontChooser.TButton",
                            command=lambda: collect_data(time.time(), time_to_collect.get()))

        start_collect_button.place(x=900, y=110, height=85, width=180)


        stop_collect_button = ttk.Button(self, text="Stop collecting", style = "FontChooser.TButton",
                            command=lambda: stop_clicked())

        choices = ["1 day", "1 week", "2 weeks"]
        time_to_collect = tk.StringVar(self)
        time_to_collect.set("1 day")
        
        option_menu = tk.OptionMenu(self, time_to_collect ,*choices)
        option_menu.config(bg = "mint cream")
        option_menu["menu"].config(bg="mint cream")
        option_menu["disabledforeground"] = "mint cream"
        option_menu["activebackground"] = "mint cream"
        option_menu["highlightbackground"] = bg_color
        
        option_menu.place(x=335, y=130, height=50, width=180)

        collect_time_label = tk.Label(self, text="Collecting time:", font=NORM_FONT, bg= bg_color)
        collect_time_label.place(x=150, y=110, height=85, width=180)

        packets_collected_label = tk.Label(self, text="Packets Collected:", font=NORM_FONT, bg= bg_color)
        

        canvas = FigureCanvasTkAgg(collecting_figure, self)
        canvas.show()

        collected_count_str = tk.StringVar()
        collected_count = tk.IntVar()
        collected_count_str.set('0')
        collected_count_label = tk.Label(self, textvariable=collected_count_str, font=NORM_FONT, bg= bg_color)
        
            
        def get_sec_to_sniff(collect_time):
            if "day" in collect_time:
                return 86400
            if "week" in collect_time:
                return 604800
            if "weeks" in collect_time:
                return 604800*2
            
        def update_collected_count():
            collected_count_str.set(str(len(packetsRead[strat_index_for_collecting:])))
            self.after(100, update_collected_count)

        
        def collect_data(start_time, collect_time):
            global strat_index_for_collecting
            global collection_thread
            strat_index_for_collecting = len(traffic_to_animate)

            packets_collected_label.place(x=150, y=110, height=85, width=180)
            collected_count_label.place(x=360, y=110, height=85, width=50)
            
            stop_collect_button.place(x=900, y=110, height=85, width=180)
            start_collect_button.place_forget()
            collect_time_label.place_forget()
            option_menu.place_forget()
            animate(0)

            canvas._tkcanvas.place(relx=0, rely =0.3, relheight = 0.7, relwidth=1)
            canvas.get_tk_widget().place(relx=0, rely =0.3, relheight = 0.7, relwidth = 1)


            sec_to_sniff = get_sec_to_sniff(collect_time)

            collect_thread = threading.Thread(target = collect_data_thread, args=(sec_to_sniff,))
            collection_thread.append(collect_thread)
            collect_thread.start()
            update_collected_count()

        def stop_clicked():
            update_stop_collecting()
            controller.show_frame(TrainPage)
       
class MainPage(tk.Frame):

    def __init__(self, parent, controller):
        
        tk.Frame.__init__(self, parent, bg=bg_color)

        label = tk.Label(self, text="Anomaly Detection", font=LARGE_FONT, bg=bg_color)
        label.pack(pady=10, padx=10)

        canvas = FigureCanvasTkAgg(f, self)
        canvas.show()

        canvas._tkcanvas.pack(side = tk.TOP, fil=tk.BOTH, expand=True)
        canvas.get_tk_widget().pack(side = tk.TOP, fil=tk.BOTH, expand=True)




packets_thread = threading.Thread(target = readPackets)
packets_thread.start()

app = AnomalyDetectionApp()
app.geometry("1280x720")
app.resizable(0, 0) # no resize
anim = animation.FuncAnimation(f, animate, interval=update_graph_seconds*1000)
anim2 = animation.FuncAnimation(collecting_figure, animate, interval=update_graph_seconds*1000)
anim3 = animation.FuncAnimation(training_figure, animate, interval=update_graph_seconds*1000)

app.mainloop()
