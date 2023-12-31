#define GTK_DISABLE_DEPRECATED
#include <gtk/gtk.h>

static void print_hello(GtkWidget *button, gpointer user_data) {
  g_print("Hello Worlds\n");
  gtk_button_set_label(GTK_BUTTON(button), "hello");
}

static void activate(GtkApplication *app, gpointer user_data) {
  GtkWidget *window;
  GtkWidget *button;
  GtkWidget *button_box;

  window = gtk_application_window_new(app);
  gtk_window_set_title(GTK_WINDOW(window), "My window!");
  gtk_window_set_default_size(GTK_WINDOW(window), 100, 100);

  button_box = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
  gtk_container_add(GTK_CONTAINER(window), button_box);

  button = gtk_button_new_with_label("Hello Worlds");
  g_signal_connect(button, "clicked", G_CALLBACK(print_hello), NULL);
  /*g_signal_connect_swapped(button, "clicked", G_CALLBACK(gtk_widget_destroy),
   * window);*/

  gtk_container_add(GTK_CONTAINER(button_box), button);

  gtk_widget_show_all(window);
}

int main(int argc, char *argv[]) {

  GtkApplication *app;
  int status;

  // create application
  app = gtk_application_new("org.gtk.application", G_APPLICATION_FLAGS_NONE);
  g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);

  // run the application
  status = g_application_run(G_APPLICATION(app), argc, argv);

  // final cleanup
  g_object_unref(app);

  return status;
}
