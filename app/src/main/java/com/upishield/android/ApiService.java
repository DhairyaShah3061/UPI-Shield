package com.upishield.android;

import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.POST;

public interface ApiService {
    @POST("api/v1/auth/login")
    Call<ApiEnvelope<AuthResponse>> login(@Body LoginRequest request);

    @POST("api/v1/analyze/message")
    Call<ApiEnvelope<MessageAnalysisResponse>> analyzeMessage(@Body MessageRequest request);

    @POST("api/v1/scan/qr")
    Call<ApiEnvelope<Object>> scanQr(@Body QrRequest request);
}
