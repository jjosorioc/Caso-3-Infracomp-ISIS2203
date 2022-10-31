import java.util.Scanner;

public class ClienteMain {
    public static void main(String[] args) throws Exception {
        System.out.println("...Starting ClienteMain...");

        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter the number of Clients:");

        int numClients = Integer.parseInt(scanner.nextLine());
        scanner.close();

        for (int i = 0; i < numClients; i++) {
            ClienteThread ct = new ClienteThread();
            ct.start();
        }

    }
}
