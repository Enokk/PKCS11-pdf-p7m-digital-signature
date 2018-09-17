from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
from os import path, remove
from app import App

# Initialize the Flask application
server = Flask(__name__)

####################################################################
#       CONFIGURATION                                              #
####################################################################
# Path to the upload directory
server.config['UPLOAD_FOLDER'] = path.join("uploads", "")
# Path to the signed files directory
server.config['SIGNED_FOLDER'] = path.join("signed", "")
# Allowed extension
server.config['ALLOWED_EXTENSIONS'] = set(['txt', 'pdf'])
# Session keys
secretKey8 = "0f3f9fcb1a10cae2"
secretKey16 = "d3e72b4bcf1c82e7fd4815c3960edf42"
####################################################################


def allowed_file(file_name):
    ''' Returns if `file_name` is of an allowed extension '''
    return '.' in file_name and \
        file_name.rsplit('.', 1)[1] in server.config['ALLOWED_EXTENSIONS']


@server.route('/')
def index():
    return render_template('index.html')


@server.route('/upload', methods=['POST'])
def upload():
    uploaded_files = request.files.getlist("file[]")
    files_to_sign = []
    for file in uploaded_files:
        if file and allowed_file(file.filename):
            # Make the filename safe, remove unsupported chars
            filename = secure_filename(file.filename)

            file.save(path.join(server.config['UPLOAD_FOLDER'], filename))
            files_to_sign.append(filename)
    
    signed_files = []
    # SIGNATURE
    for file in files_to_sign:
        signed_file = App().sign_p7m(file, server.config['SIGNED_FOLDER'] , "67393714")
        if signed_file == "":
            ## ERROR!
            pass
        signed_files.append(signed_file)
        remove(path.join(server.config['UPLOAD_FOLDER'], file))
    
    
    return render_template('upload.html', filenames=signed_files)


@server.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(
        server.config['SIGNED_FOLDER'], filename)


if __name__ == '__main__':
    server.run(
        host="127.0.0.1",
        port=int("8090"),
        debug=True
    )
