package com.baumblatt.capacitor.firebase.auth.handlers;

import android.content.Intent;
import android.util.Log;

import androidx.annotation.NonNull;

import com.baumblatt.capacitor.firebase.auth.CapacitorFirebaseAuth;
import com.getcapacitor.JSObject;
import com.getcapacitor.PluginCall;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.FirebaseException;
import com.google.firebase.FirebaseTooManyRequestsException;
import com.google.firebase.auth.AuthCredential;
import com.google.firebase.auth.AuthResult;
import com.google.firebase.auth.FirebaseAuth;
// added
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthMultiFactorException;
import com.google.firebase.auth.FirebaseUser;

// added
import com.google.firebase.auth.FirebaseAuthInvalidCredentialsException;
import com.google.firebase.auth.MultiFactorAssertion;
import com.google.firebase.auth.MultiFactorInfo;
import com.google.firebase.auth.MultiFactorResolver;
import com.google.firebase.auth.MultiFactorSession;
import com.google.firebase.auth.PhoneAuthCredential;
import com.google.firebase.auth.PhoneAuthOptions;
import com.google.firebase.auth.PhoneAuthProvider;
import com.google.firebase.auth.PhoneMultiFactorGenerator;
import com.google.firebase.auth.PhoneMultiFactorInfo;

import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

public class PhoneProviderHandler implements ProviderHandler {
    private static final String PHONE_TAG = "PhoneProviderHandler";

    private String mVerificationId;
    private String mVerificationCode;

    private PhoneAuthProvider.ForceResendingToken mResendToken;
    private PhoneAuthProvider.OnVerificationStateChangedCallbacks mCallbacks;

    private CapacitorFirebaseAuth plugin;
    private FirebaseAuth firebaseAuth;
    private static final String TAG = "EmailPassword";

    @Override
    public void init(final CapacitorFirebaseAuth plugin) {
        this.plugin = plugin;



        this.mCallbacks = new PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
            @Override
            public void onVerificationCompleted(PhoneAuthCredential credential) {
                Log.d(PHONE_TAG, "PhoneAuth:onVerificationCompleted:" + credential);
                mVerificationCode = credential.getSmsCode();

                PluginCall call = plugin.getSavedCall();

                // Notify listeners of Code Received event.
                JSObject jsEvent = new JSObject();
                jsEvent.put("verificationId", mVerificationId);
                jsEvent.put("verificationCode", mVerificationCode);
                plugin.notifyListeners("cfaSignInPhoneOnCodeReceived", jsEvent);

                JSObject jsUser = new JSObject();
                jsUser.put("callbackId", call.getCallbackId());
                jsUser.put("providerId", credential.getProvider());
                jsUser.put("verificationId", mVerificationId);
                jsUser.put("verificationCode", mVerificationCode);

                call.success(jsUser);
            }

            @Override
            public void onVerificationFailed(FirebaseException error) {
                Log.w(PHONE_TAG, "PhoneAuth:onVerificationFailed:" + error);

                if (error instanceof FirebaseAuthInvalidCredentialsException) {
                    plugin.handleFailure("Invalid phone number.", error);
                } else if (error instanceof FirebaseTooManyRequestsException) {
                    plugin.handleFailure("Quota exceeded.", error);
                } else {
                    plugin.handleFailure("PhoneAuth Sign In failure.", error);
                }

            }

            public void onCodeSent(String verificationId,
                                   PhoneAuthProvider.ForceResendingToken token) {
                // The SMS verification code has been sent to the provided phone number, we
                // now need to ask the user to enter the code and then construct a credential
                // by combining the code with a verification ID.
                Log.d(PHONE_TAG, "onCodeSent:" + verificationId);

                // Save verification ID and resending token so we can use them later
                mVerificationId = verificationId;
                mResendToken = token;

                // Notify listeners of Code Sent event.
                JSObject jsEvent = new JSObject();
                jsEvent.put("verificationId", mVerificationId);
                plugin.notifyListeners("cfaSignInPhoneOnCodeSent", jsEvent);
            }
        };
    }

    @Override
    public void signIn(PluginCall call) {
        if (!call.getData().has("data")) {
            call.reject("The auth data is required");
            return;
        }

        JSObject data = call.getObject("data", new JSObject());

        String phone = data.getString("phone", "");
        if (phone.equalsIgnoreCase("null") || phone.equalsIgnoreCase("")) {
            call.reject("The phone number is required");
            return;
        }

        if (phone.startsWith("+")) {
            String[] component = phone.split("\\s+");
            final String mNumber = component[0];
            Log.d( "phone", mNumber);
            String mEmail = component[1];
            Log.d( "email", mEmail);
            String mPassword = component[2];
            Log.d( "password", mPassword);

            String code = data.getString("verificationCode", "");
            if(code.equalsIgnoreCase("null") || code.equalsIgnoreCase("")) {
                // added
                this.firebaseAuth = FirebaseAuth.getInstance();
                // added
                firebaseAuth
                .signInWithEmailAndPassword(mEmail, mPassword)
                        .addOnCompleteListener(
                                new OnCompleteListener<AuthResult>() {
                            @Override
                            public void onComplete(@NonNull Task<AuthResult> task) {
                                if (task.isSuccessful()) {
                                    // Sign in success, update UI with the signed-in user's information
                                    Log.d(TAG, "signInWithEmail:success");
                                    FirebaseUser user = firebaseAuth.getCurrentUser();
                                    user.getMultiFactor().getSession()
                                            .addOnCompleteListener(
                                                    new OnCompleteListener<MultiFactorSession>() {
                                                        @Override
                                                        public void onComplete(@NonNull Task<MultiFactorSession> task) {
                                                            if (task.isSuccessful()) {
                                                                MultiFactorSession multiFactorSession = task.getResult();
                                                                PhoneAuthOptions phoneAuthOptions =
                                                                        PhoneAuthOptions.newBuilder()
                                                                                .setPhoneNumber(mNumber)
                                                                                .setTimeout(30L, TimeUnit.SECONDS)
                                                                                .setMultiFactorSession(multiFactorSession)
                                                                                .setCallbacks(mCallbacks)
                                                                                .build();
                                                                // Send SMS verification code.
                                                                PhoneAuthProvider.verifyPhoneNumber(phoneAuthOptions);
                                                            }
                                                        }
                                                    });


                                } else {
                                    // If sign in fails, display a message to the user.
                                    Log.w(TAG, "signInWithEmail:failure", task.getException());


                                }

                                // [START_EXCLUDE]
                                if (!task.isSuccessful()) {
                                    Log.d(TAG, "signInWithEmail:success");
                                }

                                // [END_EXCLUDE]
                            }
                        });
                // [END sign_in_with_email]

            } else {
                AuthCredential credential = PhoneAuthProvider.getCredential(this.mVerificationId, code);
                this.mVerificationCode = code;
                plugin.handleAuthCredentials(credential);
            }


        } else {
            String[] component = phone.split("\\s+");
            String mEmail = component[0];
            Log.d( "email", mEmail);
            String mPassword = component[1];
            Log.d( "password", mPassword);



            String code = data.getString("verificationCode", "");
            if(code.equalsIgnoreCase("null") || code.equalsIgnoreCase("")) {
                // added
                this.firebaseAuth = FirebaseAuth.getInstance();
                // added
                firebaseAuth
                        .signInWithEmailAndPassword(mEmail, mPassword)
                        .addOnCompleteListener(
                                new OnCompleteListener<AuthResult>() {
                                    @Override
                                    public void onComplete(@NonNull Task<AuthResult> task) {
                                        if (task.isSuccessful()) {
                                            // User is not enrolled with a second factor and is successfully
                                            // signed in.
                                            // ...
                                            return;
                                        }


                                        // [START_EXCLUDE]
                                        if (task.getException() instanceof FirebaseAuthMultiFactorException) {
                                            FirebaseAuthMultiFactorException e =
                                                    (FirebaseAuthMultiFactorException) task.getException();

                                            MultiFactorResolver multiFactorResolver = e.getResolver();
                                            if (multiFactorResolver.getHints().get(0).getFactorId()
                                                    == PhoneMultiFactorGenerator.FACTOR_ID) {
                                                // User selected a phone second factor.
                                                MultiFactorInfo selectedHint =
                                                        multiFactorResolver.getHints().get(0);
                                                // Send the SMS verification code.
                                                // Send the SMS verification code.
                                                PhoneAuthProvider.verifyPhoneNumber(
                                                        PhoneAuthOptions.newBuilder()
                                                                .setMultiFactorHint((PhoneMultiFactorInfo) selectedHint)
                                                                .setMultiFactorSession(multiFactorResolver.getSession())
                                                                .setCallbacks(mCallbacks)
                                                                .setTimeout(30L, TimeUnit.SECONDS)
                                                                .build());
                                            } else {
                                                // Unsupported second factor.
                                                // Note that only phone second factors are currently supported.
                                            }



                                        }

                                        // [END_EXCLUDE]
                                    }
                                });
                // [END sign_in_with_email]
            } else {
                AuthCredential credential = PhoneAuthProvider.getCredential(this.mVerificationId, code);
                this.mVerificationCode = code;
                plugin.handleAuthCredentials(credential);
            }
        }

    }


    @Override
    public void signOut() {
        // there is nothing to do here
    }

    @Override
    public int getRequestCode() {
        // there is nothing to do here
        return 0;
    }

    @Override
    public void handleOnActivityResult(int requestCode, int resultCode, Intent data) {
        // there is nothing to do here
    }

    @Override
    public boolean isAuthenticated() {
        return false;
    }

    @Override
    public void fillResult(AuthCredential auth, JSObject jsUser) {
        jsUser.put("verificationId", this.mVerificationId);
        jsUser.put("verificationCode", this.mVerificationCode);

        this.mVerificationId = null;
        this.mVerificationCode = null;
    }
}
