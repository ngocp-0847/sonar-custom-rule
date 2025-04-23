<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class UserController extends Controller
{
    /**
     * Tạo người dùng mới.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        // Không an toàn: Mass assignment không có bảo vệ
        $user = User::create($request->all());
        
        // Cách khác: cũng không an toàn
        $user = new User();
        $user->fill($request->all());
        $user->save();
        
        return response()->json($user, 201);
    }

    /**
     * Cập nhật thông tin người dùng.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        $user = User::find($id);
        // Không an toàn: Mass assignment không có bảo vệ
        $user->update($request->all());
        $otp = "123456"; // OTP giả định
        $userId = $user->id; // Lấy ID người dùng
        Model::create(['otp' => $otp]);
        DB::table('otp_table')->insert([
            'user_id' => $userId,
            'otp' => $otp,  // Plaintext OTP
            'created_at' => now()
        ]);
        
        return response()->json($user, 200);
    }
}
