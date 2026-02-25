import Text "mo:core/Text";
import Map "mo:core/Map";
import Array "mo:core/Array";
import Order "mo:core/Order";
import Runtime "mo:core/Runtime";
import Principal "mo:core/Principal";
import Storage "blob-storage/Storage";
import MixinAuthorization "authorization/MixinAuthorization";
import AccessControl "authorization/access-control";
import MixinStorage "blob-storage/Mixin";

actor {
  type Skill = Text;
  type Experience = {
    company : Text;
    role : Text;
    duration : Text;
    responsibilities : [Text];
  };

  public type Resume = {
    experiences : [Experience];
    skills : [Skill];
    education : [Text];
    certifications : [Text];
    languages : [Text];
  };

  type CareerGoal = {
    targetRole : Text;
    targetSkills : [Skill];
    targetIndustries : [Text];
  };

  public type UserProfile = {
    name : Text;
    careerGoals : [CareerGoal];
    uploadedResumes : [Storage.ExternalBlob];
    reviewedResumes : [Resume];
  };

  module UserProfile {
    public func compare(profile1 : UserProfile, profile2 : UserProfile) : Order.Order {
      Text.compare(profile1.name, profile2.name);
    };
  };

  type ResumeFeedback = {
    structureScore : Nat;
    contentScore : Nat;
    keywordScore : Nat;
    formattingScore : Nat;
    improvementSuggestions : [Text];
  };

  type SkillGapAnalysis = {
    missingSkills : [Skill];
    recommendedLearningPaths : [Text];
    skillMatchRate : Float;
  };

  type Conversation = {
    question : Text;
    answer : Text;
    timestamp : Int;
  };

  let accessControlState = AccessControl.initState();
  include MixinAuthorization(accessControlState);

  let userProfiles = Map.empty<Principal, UserProfile>();

  include MixinStorage();

  public query ({ caller }) func getUserProfile(user : Principal) : async ?UserProfile {
    if (caller != user and not AccessControl.isAdmin(accessControlState, caller)) {
      Runtime.trap("Unauthorized: Can only view your own profile");
    };
    switch (userProfiles.get(user)) {
      case (null) { null };
      case (?profile) { ?profile };
    };
  };

  public query ({ caller }) func getAllProfiles() : async [UserProfile] {
    if (not (AccessControl.hasPermission(accessControlState, caller, #admin))) {
      Runtime.trap("Unauthorized: Only admins can view all profiles");
    };
    userProfiles.values().toArray().sort();
  };

  public shared ({ caller }) func saveCallerUserProfile(profile : UserProfile) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can save profiles");
    };
    userProfiles.add(caller, profile);
  };

  public query ({ caller }) func getCallerUserProfile() : async ?UserProfile {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can access profiles");
    };
    switch (userProfiles.get(caller)) {
      case (null) { null };
      case (?profile) { ?profile };
    };
  };
};
