Albion_Common_Math_Vector2_o
Albion_Common_Math_AxisAlignedRectangle__l
          (Albion_Common_Math_AxisAlignedRectangle_o *__this,MethodInfo *method)

{
  Albion_Common_Math_Vector2_Fields a;
  Albion_Common_Math_Vector2_o AVar1;
  UnityEngine_Vector2_Fields UStackX_8;
    
        
  a = (__this->fields).vMax.fields;
        
  UStackX_8.x = 0.0;
  UStackX_8.y = 0.0;
  Unity_Mathematics_float2___ctor
            ((Unity_Mathematics_float2_o)&UStackX_8,0.0,
             ((__this->fields).vMax.fields.Y - (__this->fields).vMin.fields.Y) * -0.5,
             (MethodInfo *)0x0);
        
  AVar1.fields = (Albion_Common_Math_Vector2_Fields)
                 UnityEngine_Vector2__op_Addition
                           (a,(UnityEngine_Vector2_o)UStackX_8,(MethodInfo *)0x0);
  return (Albion_Common_Math_Vector2_o)AVar1.fields;
}