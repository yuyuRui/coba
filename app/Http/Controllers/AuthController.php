<?php


namespace App\Http\Controllers;
use Carbon\Carbon;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Laravel\Passport\Passport;


class AuthController extends ParentController
{
    public function login(Request $request){
        if(Auth::attempt(['email' => $request->input('email'), 'password' => $request->input('password')], true)){
            $user = Auth::user();

            Passport::tokensExpireIn(now()->addMinutes(1));
            Passport::refreshTokensExpireIn(now()->addMinutes(1));
            Passport::personalAccessTokensExpireIn(now()->addMinutes(1));

            $tokenResult = $user->createToken('Personal Access Token');
            $token = $tokenResult->token;
            $token->save();

            $success['expires_in'] = $tokenResult->token->expires_at->diffInSeconds(Carbon::now());
            $success['token'] =  $tokenResult->accessToken;
            $success['token_type'] =  "Bearer";
            return response()->json(['success' => $success], ParentController::$successCode);
        }
        else{
            Auth::logout();
            return response()->json(['error'=>'Unauthorised'], ParentController::$unauthorizedCode);
        }
    }

    public function signup(Request $request)
    {
        Auth::logout();
        $validator = Validator::make($request->all(), [
            'firstName' => 'required',
            'lastName' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required',
        ]);
        if ($validator->fails()) {
            return response()->json(['error'=>$validator->errors()], ParentController::$inputValidationErrorCode);
        }
        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = new User();
        $user->password = $input['password'];
        $user->email = $input['email'];
        $user->firstName = $input['firstName'];
        $user->lastName = $input['lastName'];
        $user->save();

        Passport::tokensExpireIn(Carbon::now()->addDays(30));
        Passport::refreshTokensExpireIn(Carbon::now()->addDays(60));
        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        $token->save();
        $success['token'] =  $tokenResult->accessToken;
        Auth::login($user);
        return response()->json(['success'=>$success], ParentController::$successCode);
    }

    public function logout() {
        Auth::logout();
        return response()->json(['success' => 'true'], ParentController::$successCode);
    }
}
