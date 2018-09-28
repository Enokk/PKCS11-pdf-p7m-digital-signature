from flask import Flask, session, render_template, request, send_from_directory  # , url_for, redirect
from werkzeug.utils import secure_filename
from os import path, remove
from shutil import move
from app import App
import json

# Initialize the Flask application
server = Flask(__name__)

####################################################################
#       CONFIGURATION                                              #
####################################################################
# Path to the upload directory
server.config["UPLOAD_FOLDER"] = path.join("uploads", "")
# Path to the signed files directory
server.config["SIGNED_FOLDER"] = path.join("signed", "")
# Allowed extension
server.config["ALLOWED_EXTENSIONS"] = set(["txt", "pdf"])
# Session keys
secretKey8 = "0f3f9fcb1a10cae2"
secretKey16 = "d3e72b4bcf1c82e7fd4815c3960edf42"
####################################################################


server.secret_key = secretKey8


def allowed_file(file_name):
    ''' Returns if `file_name` is of an allowed extension '''
    return "." in file_name and \
        file_name.rsplit(".", 1)[1] in server.config["ALLOWED_EXTENSIONS"]


@server.route("/")
def index():
    if "pin" in session and session["pin"] != "":
        return render_template("select_files.html")
    else:
        return render_template("insert_pin.html")


@server.route("/select_files", methods=["GET", "POST"])
def select_files():
    session["pin"] = request.form["pin"]
    print(session["pin"])
    return render_template("select_files.html")


@server.route("/upload", methods=["POST"])
def upload():
    uploaded_files = request.files.getlist("files[]")
    file_paths_to_sign = []
    # Foreach file uploaded
    for uploaded_file in uploaded_files:
        if uploaded_file and allowed_file(uploaded_file.filename):
            # Make the filename safe, remove unsupported chars
            file_name = secure_filename(uploaded_file.filename)
            # Save file in /upload folder
            uploaded_file_path = path.join(
                server.config["UPLOAD_FOLDER"], file_name)
            uploaded_file.save(uploaded_file_path)
            # Path added to files to sign
            file_paths_to_sign.append(uploaded_file_path)

    signed_files = []
    # Foreach file to sign
    for file_path_to_sign in file_paths_to_sign:
        # file signature
        try:
            signed_file_paths = App().sign_p7m(file_path_to_sign, session["pin"])
        except Exception as e:
            session.pop("pin")
            return render_template("upload.html", filenames=e.args)
        
        # Signed file name added to signed files
        signed_file_name = path.basename(signed_file_paths)
        signed_files.append(signed_file_name)
        # Move signed file to /signed folder
        move(signed_file_paths,
             path.join(server.config["SIGNED_FOLDER"], signed_file_name))
        # Delete uploaded file
        remove(file_path_to_sign)

    return render_template("upload.html", filenames=signed_files)


@server.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(
        server.config["SIGNED_FOLDER"], filename)


@server.route("/sign", methods=["POST"])
def sign():
    file_to_sing = request.form.get("file")
    pin = request.form.get("pin")

    data = {}
    data["file"] = file_to_sing
    data["pin"] = pin
    json_data = json.dumps(data)
    print(json_data)




if __name__ == "__main__":
    server.run(
        host="127.0.0.1",
        port=int("8090"),
        debug=True
    )
