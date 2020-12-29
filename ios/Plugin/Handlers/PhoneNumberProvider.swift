import Foundation
import Capacitor
import FirebaseAuth

class PhoneNumberProviderHandler: NSObject, ProviderHandler {
      
var plugin: CapacitorFirebaseAuth? = nil
var mPhoneNumber: String? = nil
var mVerificationId: String? = nil
var mVerificationCode: String? = nil


func initialize(plugin: CapacitorFirebaseAuth) {
    print("Initializing Phone Number Provider Handler")
    self.plugin = plugin
}

func signIn(call: CAPPluginCall) {
    
    print("Sign in on iOS")
    
    guard let data = call.getObject("data") else {
        call.reject("The auth data is required")
        return
    }

    guard let phone = data["phone"] as? String else {
        call.reject("The phone number is required")
        return
    }

    self.mPhoneNumber = phone
    
    if phone.first == "+" {
        let components = phone.split{ $0.isWhitespace }
        print("component" , components)
        let number = components[0]
        let email = components[1]
        let password = components[2]
        Auth.auth().signIn(withEmail: String(email), password: String(password)) { (result, error) in
            let authError = error as NSError?
            if authError != nil {
                call.reject("Email Sign In failure: \(String(describing: error))")
            } else {
                let user = Auth.auth().currentUser
                    user?.multiFactor.getSessionWithCompletion({ (session, error) in
                        PhoneAuthProvider.provider().verifyPhoneNumber(String(number), uiDelegate: nil, multiFactorSession: session) { (verificationID, error) in
                            if let error = error {
                                if let errCode = AuthErrorCode(rawValue: error._code) {
                                    switch errCode {
                                    case AuthErrorCode.quotaExceeded:
                                        call.reject("Quota exceeded.")
                                    case AuthErrorCode.invalidPhoneNumber:
                                        call.reject("Invalid phone number.")
                                    case AuthErrorCode.captchaCheckFailed:
                                        call.reject("Captcha Check Failed")
                                    case AuthErrorCode.missingPhoneNumber:
                                        call.reject("Missing phone number.")
                                    default:
                                        call.reject("PhoneAuth Sign In failure: \(String(describing: error))")
                                    }

                                    return
                                }
                            }

                            self.mVerificationId = verificationID

                            guard let verificationID = verificationID else {
                                call.reject("There is no verificationID after .verifyPhoneNumber!")
                                return
                            }

                            // notify event On Cond Sent.
                            self.plugin?.notifyListeners("cfaSignInPhoneOnCodeSent", data: ["verificationId" : verificationID ])

                            // return success call.
                            call.success([
                                "callbackId": call.callbackId as Any,
                                "verificationId": verificationID
                            ]);

                        }
                    })
            }
        }

    } else {
        let components = phone.split{ $0.isWhitespace }
        let email = components[0]
        let password = components[1]
        Auth.auth().signIn(withEmail: String(email),
                           password: String(password)) { (result, error) in
          let authError = error as NSError?
          if (authError == nil || authError!.code != AuthErrorCode.secondFactorRequired.rawValue) {
            // User is not enrolled with a second factor and is successfully signed in.
            // ...
          } else {
            let resolver = authError!.userInfo[AuthErrorUserInfoMultiFactorResolverKey] as! MultiFactorResolver
            // Ask user which second factor to use.
            let hint = resolver.hints[0] as! PhoneMultiFactorInfo
            // Send SMS verification code
            PhoneAuthProvider.provider().verifyPhoneNumber(
              with: hint,
              uiDelegate: nil,
              multiFactorSession: resolver.session) { (verificationID, error) in
                if let error = error {
                    if let errCode = AuthErrorCode(rawValue: error._code) {
                        switch errCode {
                        case AuthErrorCode.quotaExceeded:
                            call.reject("Quota exceeded.")
                        case AuthErrorCode.invalidPhoneNumber:
                            call.reject("Invalid phone number.")
                        case AuthErrorCode.captchaCheckFailed:
                            call.reject("Captcha Check Failed")
                        case AuthErrorCode.missingPhoneNumber:
                            call.reject("Missing phone number.")
                        default:
                            call.reject("PhoneAuth Sign In failure: \(String(describing: error))")
                        }

                        return
                    }
                }
                
                self.mVerificationId = verificationID

                guard let verificationID = verificationID else {
                    call.reject("There is no verificationID after .verifyPhoneNumber!")
                    return
                }

                // notify event On Cond Sent.
                self.plugin?.notifyListeners("cfaSignInPhoneOnCodeSent", data: ["verificationId" : verificationID ])

                // return success call.
                call.success([
                    "callbackId": call.callbackId as Any,
                    "verificationId":verificationID
                ]);
            
            }
          }
        }
    }
}

func signOut() {
    // do nothing
}

func isAuthenticated() -> Bool {
    return false
}

    func fillResult(credential: AuthCredential?, data: PluginResultData) -> PluginResultData {

    var jsResult: PluginResultData = [:]
    data.forEach { (key, value) in
        jsResult[key] = value
    }

    jsResult["phone"] = self.mPhoneNumber
    jsResult["verificationId"] = self.mVerificationId
    jsResult["verificationCode"] = self.mVerificationCode

    return jsResult

}

}
