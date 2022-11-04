<?php

namespace App\Http\Controllers;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash; // for hash password
class AuthController extends Controller
{
    public function register(Request $request){
        $fields = $request->validate([
            'name'=>'required|string',
            'email'=>'required|string|unique:users,email', //users table , email key
            'password'=>'required|string|confirmed'
        ]);

       $user = User::create([
          'name' =>$fields['name'],
          'email'=>$fields['email'],
          'password'=> bcrypt($fields['password'])
        ]);

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user'=>$user,
            'token'=>$token
        ];

        return response($response,201);
    }

    public function login(Request $request){
        $fields = $request->validate([
            'email'=>'required|string', //users table , email key
            'password'=>'required|string'
        ]);

        $user = User::Where('email',$fields['email'])->first();
        if(!$user || !Hash::check($fields['password'],$user->password)){
            return response([
                'message'=>'bad creds'
            ],401);
        }

        $token = $user->createToken('myapptoken')->plainTextToken;

        $response = [
            'user'=>$user,
            'token'=>$token
        ];

        return response($response,201);
    }

    public function logout(Request $request){
        // auth()->user()->tokens->delete();
        $user = request()->user();
         $user->tokens()->where('id', $user->currentAccessToken()->id)->delete();
        return [
            'message'=>'logged out'
        ];
    }
}
