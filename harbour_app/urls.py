from django.urls import path
from . import views
urlpatterns = [
    
  path('',views.index,name='index'),
  path('fish-list/', views.fish_list, name='fish_list'),            
  path('add/', views.fish_create, name='fish_create'),    
  path('<int:pk>/edit/', views.fish_edit, name='fish_edit'),  
  path('<int:pk>/delete/', views.fish_delete, name='fish_delete'), 
  path('api/fish/', views.FishListAPIView.as_view(), name='fish-list'),
  path('order-list/', views.order_list, name='order-list'),
  path('api/orders/', views.create_order, name='create_order'),
  path('api/register/', views.register_customer, name='register_customer'),
  path('api/login/', views.login_customer, name='login_user'),
  path('customers/', views.customersList, name='customers-list'),
  path('register/', views.register_view, name='register'),
  path('accounts/login/', views.login_view, name='login'),
  path('logout/', views.logout_view, name='logout'),
  path("api/get_customer_orders/<int:customer_id>/", views.get_customer_orders, name="get_customer_orders"),
  path('customer/<int:user_id>/addresses/', views.AddressAPI.as_view(), name='address-list'),
  path('customer/<int:user_id>/addresses/<int:address_id>/', views.AddressDetailAPI.as_view(), name='address-detail'),
  path('customer/<int:user_id>/addresses/<int:address_id>/set-default/', views.SetDefaultAddressAPI.as_view(), name='set-default-address'), 
  
path('orders/<int:user_id>/', views.UserOrderView.as_view(), name='user-orders'),
path('api/orders/<int:order_id>/action/', views.OrderActionView.as_view(), name='order-action'),
  path('api/admin/orders/', views.AdminOrderView.as_view(), name='admin-orders'),
  path('api/admin/orders/<int:order_id>/', views.AdminOrderView.as_view(), name='admin-order-update'), 
  path('toggle-delivery/<int:fish_id>/', views.toggle_delivery, name='toggle_delivery'),
  
  
  path('users/<int:user_id>/change-phone/', views.ChangePhoneNumberView.as_view(), name='change-phone'),
  path('request-reset/', views.RequestPasswordResetView.as_view()),
    path('reset-password/', views.ConfirmResetView.as_view()),
    
    path('pending-orders/', views.process_orders, name='pending_orders'),
    path('update-label/', views.update_label, name='update_label'),
path('update-labels/', views.update_labels, name='update_labels'),

path('reports/consolidated/', views.sales_report, name='consolidated_report'),
]
