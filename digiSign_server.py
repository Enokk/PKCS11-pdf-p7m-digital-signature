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
from urllib import request as urlfile
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
    return signature_type.lower() in ALLOWED_SIGNATURE_TYPES


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
        "user_id": "X" * 15,
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
def sign():
    ###################################
    # request JSON structure:
    # {
    #     user_id: user_identifier
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

    if not "user_id" in request.json:
        error_message = "missing user_id field"
        return error_response_maker(error_message, invalid_json_request, 404)
    user_id = request.json["user_id"]

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
    path_for_signed_files = request.json["output_path"]

    output_to_url = False
    if path_for_signed_files.startswith("http://"):
        output_to_url = True
    else:
        if not path.exists(path_for_signed_files) or not path.isdir(path_for_signed_files):
            error_message = f"{path_for_signed_files} field is not a valid directory"
            return error_response_maker(error_message, invalid_json_request, 404)

    # getting smart cards connected
    try:
        sessions = DigiSignLib().get_smart_cards_sessions()
    except Exception as err:
        _, value, tb = sys.exc_info()
        MyLogger().my_logger().error(value)
        MyLogger().my_logger().error(
            '\n\t'.join(f"{i}" for i in extract_tb(tb)))
        clear_pin(user_id)
        return error_response_maker(str(err),
                                    "Controllare che la smart card sia inserita correttamente",
                                    500)

    # attempt to login
    try:
        get_pin(user_id)
        session = DigiSignLib().session_login(sessions, memorized_pin[user_id]["pin"])
    except Exception as err:
        _, value, tb = sys.exc_info()
        MyLogger().my_logger().error(value)
        MyLogger().my_logger().error(
            '\n\t'.join(f"{i}" for i in extract_tb(tb)))
        clear_pin(user_id)
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

        # handle url file paths
        if file_path_to_sign.startswith("http://"):
            try:
                local_file_path = downoad_file(file_path_to_sign)
            except:
                MyLogger().my_logger().error(f"Impossibile reperire il file: {file_path_to_sign}")
                _, value, tb = sys.exc_info()
                MyLogger().my_logger().error(value)
                MyLogger().my_logger().error(
                    '\n\t'.join(f"{i}" for i in extract_tb(tb)))
                signed_files_list[index]["signed"] = "no"
                continue
        else:
            local_file_path = file_path_to_sign

        try:
            if signature_type == P7M:
                # p7m signature
                temp_file_path = DigiSignLib().sign_p7m(local_file_path, session, user_id)
            elif signature_type == PDF:
                # pdf signature
                # TODO
                pass

            signed_files_list[index]["signed"] = "yes"
        except:
            _, value, tb = sys.exc_info()
            MyLogger().my_logger().error(value)
            MyLogger().my_logger().error(
                '\n\t'.join(f"{i}" for i in extract_tb(tb)))
            signed_files_list[index]["signed"] = "no"
            continue

        # moving signed file to given destination
        if output_to_url:
            with open(temp_file_path, "rb") as _file:
                files = {'file': _file}
                try:
                    MyLogger().my_logger().info(path_for_signed_files)
                    res = post(path_for_signed_files, files=files)
                except:
                    _, value, tb = sys.exc_info()
                    MyLogger().my_logger().error(value)
                    MyLogger().my_logger().error(
                        '\n\t'.join(f"{i}" for i in extract_tb(tb)))
                    signed_files_list[index]["signed_file"] = "EXCEPTION!!"
                    continue 
                if res.status_code != 200:
                    error_message = res.json()["error_message"]
                    MyLogger().my_logger().error(error_message)
                    signed_files_list[index]["signed_file"] = "ERROR!!"
                    continue
                else:
                    signed_files_list[index]["signed"] = "yes - [remote]"
                    uploaded_path = res.json()["Ok"]
                    signed_files_list[index]["signed_file"] = f"{uploaded_path}"
                    continue
        else:
            temp_file_name = path.basename(temp_file_path)
            signed_file_path = path.join(
                path_for_signed_files, temp_file_name)
            try:
                move(temp_file_path, signed_file_path)
                signed_files_list[index]["signed_file"] = signed_file_path
            except:
                _, value, tb = sys.exc_info()
                MyLogger().my_logger().error(value)
                MyLogger().my_logger().error(
                    '\n\t'.join(f"{i}" for i in extract_tb(tb)))
                signed_files_list[index]["signed_file"] = "LOST"
                continue

    # logout
    try:
        DigiSignLib().session_logout(session)
    except:
        MyLogger().my_logger().error("logout failed")
    # session close
    try:
        DigiSignLib().session_close(session)
    except:
        MyLogger().my_logger().error("session close failed")
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
def clear_pin(user_id):
    MyLogger().my_logger().info("Clearing PIN")
    if user_id in memorized_pin:
        if "timestamp" in memorized_pin[user_id]:
            memorized_pin[user_id].pop("timestamp")
        if "pin" in memorized_pin[user_id]:
            memorized_pin[user_id].pop("pin")


def get_pin(user_id):
    ''' Gets you the `PIN` '''

    if user_id not in memorized_pin:
        memorized_pin[user_id] = {}

    if "pin" not in memorized_pin[user_id]:
        _get_pin_popup(user_id)
    elif not _is_pin_valid(user_id):
        MyLogger().my_logger().info("Invalidating PIN")
        clear_pin(user_id)
        _get_pin_popup(user_id)
    else:
        MyLogger().my_logger().info("Refreshing PIN")
        memorized_pin[user_id]["timestamp"] = datetime.now()

    # check for mishapening
    if "pin" not in memorized_pin[user_id]:
        raise ValueError("No pin inserted")


def _is_pin_valid(user_id):
    ''' Check if `PIN` is expired '''

    return datetime.now() < memorized_pin[user_id]["timestamp"] + timedelta(seconds=PIN_TIMEOUT)


def _get_pin_popup(user_id):
    ''' Little popup to input Smart Card PIN '''

    MyLogger().my_logger().info("User PIN input")
    widget = Tk()
    row = Frame(widget)
    label = Label(row, width=10, text="Insert PIN")
    pinbox = Entry(row, width=15, show='*')
    row.pack(side="top", padx=60, pady=20)
    label.pack(side="left")
    pinbox.pack(side="right")

    def on_enter(evt):
        on_click()

    def on_click():
        memorized_pin[user_id]["pin"] = pinbox.get()
        memorized_pin[user_id]["timestamp"] = datetime.now()
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


def downoad_file(file_url):
    # get file name
    file_name = file_url.rsplit('/', 1)[1]
    # get file content
    url_content = urlfile.urlopen(file_url).read()
    # create file locally
    if not path.exists(UPLOAD_FOLDER) or not path.isdir(UPLOAD_FOLDER):
        makedirs(UPLOAD_FOLDER)
    file_path = path.join(UPLOAD_FOLDER, file_name)
    with open(file_path, "wb") as _file:
        _file.write(url_content)

    return file_path


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
