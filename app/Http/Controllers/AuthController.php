<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Exception;
use Illuminate\Http\Response;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;

class AuthController extends Controller
{
    // função para criação do usuário
    public function register(Request $request){
        // a função 'only' filtra o array dado e retorna apenas os itens que correspondem às chaves especificadas
        $data = $request->only('name', 'email', 'password');
        // valida os dados retornados na requisição a partir do Laravel (há também o Form Requests)
        $validator = Validator::make($data, [
            'name' => 'required|string',
            'email' => 'required|string|unique:users_auth,email',
            'password' => 'required|string|min:6|max:50',
        ]);
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }
        try{
        // criação do usuário no banco de dados a partir do método do Eloquent ORM
            $user = User::create([
                'name' => $data['name'],
                'email' => $data['email'],
                'password' => $data['password'],
            ]);
            // retorno da resposta
            return response()->json([
                'success' => true,
                'message' => 'User created successfully',
                'data' => $user
            ], Response::HTTP_OK);
        } catch (\Exception $e){
            return response()->json(['error' => 'Unable to create user.'], 500);
        }
    }
    // função para login do usuário
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

         // Validação dos dados
        $validator = Validator::make($credentials, [
            'email' => 'required|email',
            'password' => 'required|string|min:6|max:50',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        // Tente encontrar o usuário pelo e-mail
        $user = User::where('email', $credentials['email'])->first();

        try {
            if ($user && Hash::check($request->input('password'), $user->password)) {
                // Senha correta, prossiga com a autenticação
                // Criação de token
                
                if (!$token = JWTAuth::attempt(['email' => $request->input('email'), 'password' => $request->input('password')])) {
                    return response()->json([
                        'success' => false,
                        'message' => 'Login credentials are invalid.'
                    ], 401); // 401: credenciais inválidas
                }
                $token = JWTAuth::fromUser($user);
            } else {
                // Senha incorreta
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid credentials',
                ], 401);
            }
            } catch (JWTException $err) {
                return response()->json([
                    'success' => false,
                    'message' => 'Could not create token'
                ], 500);
            }
        
            return response()->json([
                'success' => true,
                'authorization' => [
                    'token' => $token,
                    'type' => 'bearer',
                ]
            ]);
        // return response()->json([
        //     'success' => true,
        //     'message' => 'Invalid credentials',
        //     'data' =>  $user && Hash::check($request->input('password'), $user->PASSWORD)
        // ], 200);
       
    }    
    public function logout(Request $request){
        $validator = Validator::make($request->only('token'), [
            'token' => 'required'
        ]);
        if($validator->fails()){
            return response()->json([
                'error' => $validator->message()
            ], 200);
        }
        try {
            JWTAuth::invalidate($request->token);
            return response()->json([
                'success' => true,
                'message' => 'User has been logged out'
            ]);
        } catch(Exception $err){
            return response()->json([
                'success' => false,
                'message' => 'User cannot be logged out'
            ]);
        }
    }
    public function list(Request $request){
        $token = $request->bearerToken();
        if (!$token) {
            return response()->json(['error' => 'Authorization token not found'], 401);
        }
    
        try {
            // Tenta autenticar o usuário com o token
            $user = JWTAuth::authenticate($token);
        } catch (TokenExpiredException $e) {
            return response()->json(['error' => 'Token expired'], 401);
        } catch (TokenInvalidException $e) {
            return response()->json(['error' => 'Token invalid'], 401);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Token not provided'], 401);
        }
    
        // Agora que o usuário está autenticado, você pode buscar a lista de usuários
        $users = DB::table('users_auth')->get();
        return response()->json($users);
}}
