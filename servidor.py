from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from functools import wraps
from flask import redirect, url_for
import openai


openai.api_key = 'sua_chave_de_api_do_openai'

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})  # Correcting CORS configuration
app.config['SECRET_KEY'] = 'qualquer'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:password@localhost:'
db = SQLAlchemy(app)
login_manager = LoginManager(app)




class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuarios'
    idUsuario = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(250))
    lastName = db.Column(db.String(250))
    email = db.Column(db.String(450), unique=True)
    senha = db.Column(db.String(50))
    telefone = db.Column(db.String(50))
    genero = db.Column(db.String(50))

    def get_id(self):
        return str(self.idUsuario)  # Implementing get_id method for Flask-Login


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))




@app.route('/home', methods=['POST'])
def home():
   
    
    # Obtém o nome e sobrenome do usuário autenticado
    nome = current_user.firstName
    sobrenome = current_user.lastName

    
    return jsonify({'nome': nome, 'sobrenome': sobrenome})





@app.route('/login', methods=['POST'])
def process_login():
    email = request.json.get('email')
    password = request.json.get('password')
    print(f"Tentativa de login com email: {email}")

    usuario = Usuario.query.filter_by(email=email).first()

    if usuario:
        if usuario.senha == password:
            login_user(usuario)
            return jsonify({'message': 'Login bem-sucedido'}), 200
        else:
            print("Senha incorreta.")
            return jsonify({'message': 'Senha incorreta'}), 401
    else:
        print("Usuário não encontrado.")
        return jsonify({'message': 'Usuário não encontrado'}), 401



@app.route('/cadastro', methods=['POST'])
def process_cadastro():
    data = request.get_json()

    pNome = data.get('pNome')
    sNome = data.get('sNome')
    email = data.get('email')
    telefone = data.get('telefone')
    senha = data.get('senha')
    genero = data.get('genero')
   
    print(f"Tentativa de cadastro com email: {email}")

    usuario_existente = Usuario.query.filter_by(email=email).first()

    if usuario_existente:
        print("E-mail já cadastrado.")
        return jsonify({'message': 'E-mail já cadastrado'}), 409

    novo_usuario = Usuario(
        firstName=pNome,
        lastName=sNome,
        email=email,
        telefone=telefone,
        senha=senha,
        genero=genero  
    )

    db.session.add(novo_usuario)
    db.session.commit()

    return jsonify({'message': 'Usuário cadastrado com sucesso'}), 201

@app.route('/check-auth', methods=['GET'])
def check_authentication():
    if current_user.is_authenticated:
        print("Usuário autenticado.")
        return jsonify({'authenticated': True})
    else:
        print("Usuário não autenticado.")
        return jsonify({'authenticated': False})
    
    
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    print("Usuário deslogado.")
    return jsonify({'message': 'Usuário deslogado com sucesso'}), 200

if __name__ == '__main__':
    app.run(debug=True)