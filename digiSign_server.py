from datetime import datetime, timedelta
from digiSign_lib import DigiSignLib
from flask import Flask, render_template, request, send_from_directory, make_response, Response, jsonify
from flask_cors import CORS, cross_origin
from my_config_loader import MyConfigLoader
from my_logger import MyLogger
from os import path, remove, sys, listdir, fsdecode, makedirs
from requests import post
from shutil import move
from tkinter import Tk, Entry, Label, Button, Frame
from traceback import extract_tb
from werkzeug.utils import secure_filename
from zipfile import ZipFile


####################################################################
#       CONFIGURATION                                              #
####################################################################
# url
HOST = MyConfigLoader().get_server_config()["host"]
PORT = MyConfigLoader().get_server_config()["port"]
# mapped directories
TEMPLATE_FOLDER = MyConfigLoader().get_server_config()["template_folder"]
UPLOAD_FOLDER = MyConfigLoader().get_server_config()["uploaded_file_folder"]
SIGNED_FOLDER = MyConfigLoader().get_server_config()["signed_file_folder"]
LOGS_FOLDER = MyConfigLoader().get_logger_config()["log_folder"]
# Allowed signature types
P7M = "p7m"
PDF = "pdf"
ALLOWED_SIGNATURE_TYPES = set([P7M, PDF])
# Memorized pin
memorized_pin = {}
PIN_TIMEOUT = MyConfigLoader().get_server_config()["pin_validity_time"]
####################################################################


# Initialize the Flask application
server = Flask(__name__, template_folder=TEMPLATE_FOLDER)
# enable CORS for /api/*
CORS(server, resources={r"/api/*": {"origins": "*"}})


def allowed_signature(signature_type):
    ''' Returns if `signature_type` is allowed '''
    return signature_type in ALLOWED_SIGNATURE_TYPES


def error_response_maker(error_message, user_tip, status):
    ''' Returns an HTTP error response with HTTP_status = `status`.

            body structure:

            {
                error_message: error_message,
                user_tip: user_tip
            }
    '''

    MyLogger().my_logger().error(error_message)
    return make_response(jsonify({"error_message": error_message, "user_tip": user_tip}), status)


####################################################################
#       SIGN WEB                                                   #
####################################################################
@server.route("/")
def index():
    return render_template("select_files.html")


@server.route("/upload", methods=["POST"])
def upload():
    uploaded_files = request.files.getlist("files[]")
    output_type = request.form["type"]

    # Check for upload and signed folder
    if not path.exists(UPLOAD_FOLDER) or not path.isdir(UPLOAD_FOLDER):
        makedirs(UPLOAD_FOLDER)
    if not path.exists(SIGNED_FOLDER) or not path.isdir(SIGNED_FOLDER):
        makedirs(SIGNED_FOLDER)

    # Folders cleanup
    for _file in listdir(UPLOAD_FOLDER):
        remove(path.join(UPLOAD_FOLDER, _file))
    for _file in listdir(SIGNED_FOLDER):
        remove(path.join(SIGNED_FOLDER, _file))

    file_paths_to_sign = []
    # Foreach file uploaded
    for uploaded_file in uploaded_files:
        if uploaded_file:
            # Make the filename safe, remove unsupported chars
            file_name = secure_filename(uploaded_file.filename)
            # Save file in /upload folder
            uploaded_file_path = path.join(UPLOAD_FOLDER, file_name)
            uploaded_file.save(uploaded_file_path)
            # Path added to files to sign
            file_paths_to_sign.append(uploaded_file_path)

    json_request = {
        "file_list": [],
        "output_path": SIGNED_FOLDER,
        "signed_file_type": output_type
    }

    for _file in file_paths_to_sign:
        json_request["file_list"].append(_file)

    url = f"http://{HOST}:{PORT}/api/sign"
    res = post(url=url, json=json_request,
               headers={'Content-Type': 'application/json'})

    if res.status_code != 200:
        user_tip = res.json()["user_tip"]
        return render_template("error_page.html", usertip=user_tip)

    signed_files_list = []
    not_signed_files_list = []
    for item in res.json()["signed_file_list"]:
        if item["signed"] == "yes":
            file_name = path.basename(item["signed_file"])
            signed_files_list.append(file_name)
        else:
            not_signed_files_list.append(item["file_to_sign"])

    return render_template("upload.html", filenames=signed_files_list,
                           errornames=not_signed_files_list)


@server.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(SIGNED_FOLDER, filename)


@server.route("/easylog")
def zip_and_download_logs():
    today = datetime.now().strftime("%Y%B%d")
    log_zip_name = f"{today}_log.zip"

    # old zip cleanup
    for _file in listdir(LOGS_FOLDER):
        if fsdecode(_file).find(".zip") > 0:
            remove(path.join(LOGS_FOLDER, _file))

    # generate zip file
    with ZipFile(path.join(LOGS_FOLDER, log_zip_name), "w") as zip:
        for _file in listdir(LOGS_FOLDER):
            # keep only .log files
            if fsdecode(_file).find(".log") > 0:
                zip.write(path.join(LOGS_FOLDER, _file), arcname=_file)

    # zip download
    return send_from_directory(LOGS_FOLDER, log_zip_name)


####################################################################
#       REST SIGN API                                              #
####################################################################
@server.route("/api/sign", methods=["POST"])
@cross_origin()
def sign(req={}):
    ###################################
    # request JSON structure:
    # {
    #     file_list: [file_path1, file_path2, ...],
    #     signed_file_type: p7m|pdf,
    #     output_path: output_folder_path
    # }
    ###################################
    MyLogger().my_logger().info("/api/sign request")

    # check for well formed request JSON
    invalid_json_request = "Richiesta al server non valida, contatta l'amministratore di sistema"

    if not request.json:
        error_message = "Missing json request structure"
        return error_response_maker(error_message, invalid_json_request, 404)

    if not "file_list" in request.json:
        error_message = "missing file_list field"
        return error_response_maker(error_message, invalid_json_request, 404)
    file_list = request.json["file_list"]

    if not isinstance(file_list, (list,)) or len(file_list) < 1:
        error_message = "Empty file_list"
        return error_response_maker(error_message, invalid_json_request, 404)

    if not "signed_file_type" in request.json:
        error_message = "missing signed_file_type field"
        return error_response_maker(error_message, invalid_json_request, 404)
    signature_type = request.json["signed_file_type"]

    if not allowed_signature(signature_type):
        error_message = f"{signature_type} not allowed in signed_file_type field"
        return error_response_maker(error_message, invalid_json_request, 404)

    if not "output_path" in request.json:
        error_message = "missing output_path field"
        return error_response_maker(error_message, invalid_json_request, 404)
    path_for_signed_files_list = request.json["output_path"]

    if not path.exists(path_for_signed_files_list) or not path.isdir(path_for_signed_files_list):
        error_message = f"{path_for_signed_files_list} field is not a valid directory"
        return error_response_maker(error_message, invalid_json_request, 404)

    # getting smart cards connected
    try:
        sessions = DigiSignLib().get_smart_cards_sessions()
    except Exception as err:
        _, _, tb = sys.exc_info()
        MyLogger().my_logger().error(
            '\n\t'.join(f"{i}" for i in extract_tb(tb)))
        clear_pin()
        return error_response_maker(str(err),
                                    "Controllare che la smart card sia inserita correttamente",
                                    500)

    # attempt to login
    try:
        get_pin()
        session = DigiSignLib().session_login(sessions, memorized_pin["pin"])
    except Exception as err:
        _, _, tb = sys.exc_info()
        MyLogger().my_logger().error(
            '\n\t'.join(f"{i}" for i in extract_tb(tb)))
        clear_pin()
        return error_response_maker(str(err),
                                    "Controllare che il pin sia valido e corretto",
                                    500)

    # loop on given files
    signed_files_list = []
    for index, file_path_to_sign in enumerate(file_list):
        # initialize response structure
        output_item = {"file_to_sign": file_path_to_sign,
                       "signed": "",
                       "signed_file": ""}
        signed_files_list.append(output_item)

        try:
            if signature_type == P7M:
                # p7m signature
                temp_file_path = DigiSignLib().sign_p7m(file_path_to_sign, session)
            elif signature_type == PDF:
                # pdf signature
                # TODO
                pass

            signed_files_list[index]["signed"] = "yes"
        except:
            _, _, tb = sys.exc_info()
            MyLogger().my_logger().error(
                '\n\t'.join(f"{i}" for i in extract_tb(tb)))
            signed_files_list[index]["signed"] = "no"
            continue

        # moving signed file to given destination
        temp_file_name = path.basename(temp_file_path)
        signed_file_path = path.join(
            path_for_signed_files_list, temp_file_name)
        try:
            move(temp_file_path, signed_file_path)
            signed_files_list[index]["signed_file"] = signed_file_path
        except:
            _, _, tb = sys.exc_info()
            MyLogger().my_logger().error(
                '\n\t'.join(f"{i}" for i in extract_tb(tb)))
            signed_files_list[index]["signed_file"] = "LOST"
            continue

    try:
        DigiSignLib().session_logout(session)
    except:
        MyLogger().my_logger().warning("logout failed")
    ###################################
    # response JSON structure:
    # { signed_file_list: [
    #     {
    #         file_to_sign: ***,
    #         signed: yes|no,
    #         signed_file: ***
    #     },
    #     {
    #         file_to_sign: ***,
    #         signed: yes|no,
    #         signed_file: ***
    #     },
    #     ...
    # ]}
    ###################################
    res = make_response(jsonify({"signed_file_list": signed_files_list}))
    return res


####################################################################
#       UTILITIES                                                  #
####################################################################
def clear_pin():
    MyLogger().my_logger().info("Clearing PIN")
    if "timestamp" in memorized_pin:
        memorized_pin.pop("timestamp")
    if "pin" in memorized_pin:
        memorized_pin.pop("pin")


def get_pin():
    ''' Gets you the `PIN` '''

    if "pin" not in memorized_pin:
        _get_pin_popup()
    elif not _is_pin_valid():
        MyLogger().my_logger().info("Invalidating PIN")
        clear_pin()
        _get_pin_popup()
    else:
        MyLogger().my_logger().info("Refreshing PIN")
        memorized_pin["timestamp"] = datetime.now()

    # check for mishapening
    if "pin" not in memorized_pin:
        raise ValueError("No pin inserted")


def _is_pin_valid():
    ''' Check if `PIN` is expired '''

    return datetime.now() < memorized_pin["timestamp"] + timedelta(seconds=PIN_TIMEOUT)


def _get_pin_popup():
    ''' Little popup to input Smart Card PIN '''

    MyLogger().my_logger().info("USer PIN input")
    widget = Tk()
    row = Frame(widget)
    label = Label(row, width=10, text="Insert PIN")
    pinbox = Entry(row, width=15, show='*')
    row.pack(side="top", padx=60, pady=20)
    label.pack(side="left")
    pinbox.pack(side="right")

    def on_enter(evt):
        memorized_pin["pin"] = pinbox.get()
        memorized_pin["timestamp"] = datetime.now()
        widget.destroy()

    def on_click():
        memorized_pin["pin"] = pinbox.get()
        memorized_pin["timestamp"] = datetime.now()
        widget.destroy()

    pinbox.bind("<Return>", on_enter)
    button = Button(widget, command=on_click, text="OK")
    button.pack(side="top", fill="x", padx=80)
    filler = Label(widget, height=1, text="")
    filler.pack(side="top")

    widget.title("Smart Card PIN")
    widget.attributes("-topmost", True)
    widget.update()
    _center(widget)
    widget.mainloop()


def _center(widget):
    ''' Center `widget` on the screen '''
    screen_width = widget.winfo_screenwidth()
    screen_height = widget.winfo_screenheight()

    x = screen_width / 2 - widget.winfo_width() / 2
    # Little higher than center
    y = screen_height / 2 - widget.winfo_height()

    widget.geometry(f"+{int(x)}+{int(y)}")


####################################################################
#       SERVER STARTUP                                             #
####################################################################
def server_start():
    MyLogger().my_logger().info("Server started!")

    try:
        server.run(
            host=HOST,
            port=PORT,
            debug=False
        )
    except:
        MyLogger().my_logger().error("Impossible to start Server")
        pass


if __name__ == "__main__":
    server_start()
