package com.upishield.android;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import okhttp3.OkHttpClient;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.gson.GsonConverterFactory;

public class MainActivity extends AppCompatActivity {
    private static final String BASE_URL = "http://10.0.2.2:8080/";
    private static final String PREFS = "upi_shield_prefs";
    private static final String TOKEN = "token";

    private ApiService api;
    private TextView statusText;
    private TextView resultText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusText = findViewById(R.id.statusText);
        resultText = findViewById(R.id.resultText);
        resultText.setMovementMethod(new ScrollingMovementMethod());

        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        String token = prefs.getString(TOKEN, null);

        OkHttpClient client = new OkHttpClient.Builder()
                .addInterceptor(chain -> {
                    okhttp3.Request original = chain.request();
                    okhttp3.Request.Builder builder = original.newBuilder();
                    String currentToken = getSharedPreferences(PREFS, MODE_PRIVATE).getString(TOKEN, null);
                    if (currentToken != null) {
                        builder.header("Authorization", "Bearer " + currentToken);
                    }
                    return chain.proceed(builder.build());
                })
                .build();

        Retrofit retrofit = new Retrofit.Builder()
                .baseUrl(BASE_URL)
                .client(client)
                .addConverterFactory(GsonConverterFactory.create())
                .build();
        api = retrofit.create(ApiService.class);

        statusText.setText(token == null
                ? "Signed out. Sign in to use the safety checks."
                : "Signed in. Ready for a safety check.");

        findViewById(R.id.loginButton).setOnClickListener(view -> showLoginDialog());
        findViewById(R.id.scanButton).setOnClickListener(view -> startQrScan());
        findViewById(R.id.analyzeButton).setOnClickListener(view -> analyzeMessage());
    }

    private void showLoginDialog() {
        View view = LayoutInflater.from(this).inflate(R.layout.dialog_login, null);
        EditText email = view.findViewById(R.id.emailInput);
        EditText password = view.findViewById(R.id.passwordInput);

        new AlertDialog.Builder(this)
                .setTitle("Sign in")
                .setView(view)
                .setPositiveButton("Sign in", (dialog, which) -> {
                    String emailValue = email.getText().toString().trim();
                    String passwordValue = password.getText().toString();
                    if (emailValue.isEmpty() || passwordValue.isEmpty()) {
                        Toast.makeText(this, "Email and password are required", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    api.login(new LoginRequest(emailValue, passwordValue)).enqueue(new Callback<ApiEnvelope<AuthResponse>>() {
                        @Override
                        public void onResponse(Call<ApiEnvelope<AuthResponse>> call, Response<ApiEnvelope<AuthResponse>> response) {
                            if (response.isSuccessful() && response.body() != null && response.body().data != null) {
                                getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                                        .putString(TOKEN, response.body().data.token)
                                        .apply();
                                statusText.setText("Signed in. Ready for a safety check.");
                            } else {
                                resultText.setText("Sign-in failed. Check the server and credentials.");
                            }
                        }

                        @Override
                        public void onFailure(Call<ApiEnvelope<AuthResponse>> call, Throwable throwable) {
                            resultText.setText("Sign-in could not reach the backend: " + throwable.getMessage());
                        }
                    });
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void startQrScan() {
        IntentIntegrator integrator = new IntentIntegrator(this);
        integrator.setPrompt("Scan a UPI or link QR");
        integrator.setOrientationLocked(true);
        integrator.initiateScan();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, @Nullable android.content.Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        if (result != null && result.getContents() != null) {
            api.scanQr(new QrRequest(result.getContents())).enqueue(new Callback<ApiEnvelope<Object>>() {
                @Override
                public void onResponse(Call<ApiEnvelope<Object>> call, Response<ApiEnvelope<Object>> response) {
                    if (response.isSuccessful() && response.body() != null) {
                        resultText.setText(response.body().message == null
                                ? "QR scanned."
                                : response.body().message + "\n\n" + formatJson(response.body().data));
                    } else {
                        resultText.setText("QR rejected or analysis failed.");
                    }
                }

                @Override
                public void onFailure(Call<ApiEnvelope<Object>> call, Throwable throwable) {
                    resultText.setText("QR analysis could not reach the backend: " + throwable.getMessage());
                }
            });
        }
    }

    private void analyzeMessage() {
        EditText messageInput = findViewById(R.id.messageInput);
        String content = messageInput.getText().toString().trim();
        if (content.isEmpty()) {
            Toast.makeText(this, "Paste a message first", Toast.LENGTH_SHORT).show();
            return;
        }

        api.analyzeMessage(new MessageRequest(content)).enqueue(new Callback<ApiEnvelope<MessageAnalysisResponse>>() {
            @Override
            public void onResponse(Call<ApiEnvelope<MessageAnalysisResponse>> call, Response<ApiEnvelope<MessageAnalysisResponse>> response) {
                if (response.isSuccessful() && response.body() != null && response.body().data != null) {
                    MessageAnalysisResponse data = response.body().data;
                    StringBuilder text = new StringBuilder();
                    text.append("Signals detected: ").append(data.signalCount).append('\n');
                    text.append("PIN/refund request: ").append(data.pinRequestDetected).append('\n');
                    text.append("Remote app request: ").append(data.remoteAppDetected).append('\n');
                    text.append("Urgency/threat: ").append(data.urgencyDetected).append('\n');
                    if (data.signals != null && !data.signals.isEmpty()) {
                        text.append('\n');
                        for (SocialEngineeringSignal signal : data.signals) {
                            text.append(signal.severity).append(": ").append(signal.description).append('\n');
                        }
                    }
                    resultText.setText(text.toString());
                } else {
                    resultText.setText("The message was rejected or could not be analyzed.");
                }
            }

            @Override
            public void onFailure(Call<ApiEnvelope<MessageAnalysisResponse>> call, Throwable throwable) {
                resultText.setText("Message analysis could not reach the backend: " + throwable.getMessage());
            }
        });
    }

    private String formatJson(Object data) {
        if (data == null) {
            return "";
        }
        return data.toString();
    }
}
